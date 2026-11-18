"""Self-check: re-open the copies and look for anything sensitive that survived.

Two independent checks, both value-free:

1. **Pattern scan** -- re-run the value regexes over the copy. Any hit is a
   detector miss or a failed redaction.
2. **Known-value scan** -- the engine records a salted-free SHA-256 digest of
   every value it redacted. Any of those tokens still present in the copy means
   the same value appeared somewhere that was not marked.

A token only counts as a leak if it is *not* part of the copy's general vocabulary
(words that legitimately appear outside redacted regions). Without that filter
every redacted "OPEN" or "CAPITAL" would be reported and real leaks would drown.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

import pymupdf

from .layout import cells_from_words, page_cells
from .patterns import PATTERNS, PLACEHOLDER_RE, h, is_date_like, norm

_WORD_RE = re.compile(r"\S+")


def tokens(text: str) -> set[str]:
    """Normalised word tokens, for comparing a copy against its source."""
    return {norm(t) for t in _WORD_RE.findall(text or "") if t.strip()}


def _count_pattern_hits(text: str, source_vocab: set[str] | None = None) -> Counter:
    """Re-run the value regexes, minus hits that are plainly not identifiers.

    `source_vocab` is the token set of the *input*. A pattern that appears only
    in the copy is not a leak, it is the reader's own noise: tesseract will
    read a sideways line as "H3LVMA100" and that is indistinguishable from a
    value -- unless the document you were handed never contained it.
    """
    hits: Counter = Counter()
    for label, rx in PATTERNS:
        for m in rx.finditer(text):
            if label == "NUMBER" and is_date_like(m.group(0)):
                continue          # "2023-10-04" is a date, not an account number
            if source_vocab is not None and norm(m.group(0)) not in source_vocab:
                continue          # only exists in this render, not in the input
            hits[label] += 1
    return hits


@dataclass
class VerificationReport:
    pattern_hits: Counter = field(default_factory=Counter)
    leak_total: int = 0
    leaks_by_category: Counter = field(default_factory=Counter)
    masked_samples: list[tuple[str, int, str]] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return self.leak_total == 0 and not any(self.pattern_hits.values())

    def merge(self, other: VerificationReport) -> VerificationReport:
        """Fold another pass (e.g. a deep pixel re-scan) into this report."""
        self.pattern_hits.update(other.pattern_hits)
        self.leak_total += other.leak_total
        self.leaks_by_category.update(other.leaks_by_category)
        self.masked_samples.extend(other.masked_samples[:25])
        return self

    def as_dict(self) -> dict:
        return {
            "residual_pattern_hits": {k: v for k, v in self.pattern_hits.items() if v},
            "residual_known_value_hits": self.leak_total,
            "by_category": dict(self.leaks_by_category),
        }


def _mask(tok: str) -> str:
    return tok[:1] + "*" * max(0, len(tok) - 2) + tok[-1:]


def _scan_text(report: VerificationReport, text: str, redacted_hashes: dict,
               unredacted_vocab: set[str], sample_limit: int,
               source_vocab: set[str] | None = None) -> None:
    """Pattern hits and remembered-value hits for one run of text."""
    report.pattern_hits.update(_count_pattern_hits(text, source_vocab))
    seen = set()
    for m in _WORD_RE.finditer(text):
        tok = m.group(0)
        if tok in seen or PLACEHOLDER_RE.fullmatch(tok):
            continue                      # our own placeholder is not a leak
        cat = (redacted_hashes.get(h(tok))
               or redacted_hashes.get(h(tok.strip(".,:;()"))))
        if cat and norm(tok) in unredacted_vocab:
            cat = None                    # generic word, not a value
        if not cat:
            continue
        seen.add(tok)
        report.leak_total += 1
        report.leaks_by_category[cat] += 1
        if len(report.masked_samples) < sample_limit:
            report.masked_samples.append((cat, len(tok), _mask(tok)))


def _object_strings(doc) -> list[str]:
    """Strings that live outside the content stream: annots, fields, bookmarks."""
    out: list[str] = []
    for page in doc:
        try:
            for annot in page.annots() or []:
                info = annot.info or {}
                out += [info.get("content") or "", info.get("subject") or "",
                        info.get("title") or ""]
        except Exception:
            pass
        try:
            for widget in page.widgets() or []:
                out.append(getattr(widget, "field_value", "") or "")
        except Exception:
            pass
    try:
        out += [title for _lvl, title, _p in (doc.get_toc() or [])]
    except Exception:
        pass
    return [s for s in out if s]


def scan_copy(path, redacted_hashes: dict[str, str],
              unredacted_vocab: set[str], sample_limit: int = 25,
              source_vocab: set[str] | None = None) -> VerificationReport:
    """Look for leaks in one redacted copy: text layer, then object strings."""
    report = VerificationReport()
    with pymupdf.open(path) as doc:
        for page in doc:
            for cell in page_cells(page):
                _scan_text(report, cell["text"], redacted_hashes,
                           unredacted_vocab, sample_limit, source_vocab)
        for text in _object_strings(doc):
            _scan_text(report, text, redacted_hashes, unredacted_vocab, sample_limit,
                       source_vocab)
    return report


def ocr_rescan(path, redacted_hashes: dict[str, str], unredacted_vocab: set[str],
               dpi: int = 200, lang: str = "eng", sample_limit: int = 25,
               rects_by_page: dict | None = None,
               source_vocab: set[str] | None = None):
    """Deep check: OCR the copy's *pixels* and look for redacted values again.

    On a scan the text layer is ours (we wrote it), so scanning it proves only that
    we are consistent. This re-reads the picture, which is the thing a leak would
    hide in.

    `rects_by_page` limits the work to the pages (and boxes) that were OCR'd:
    ``{page_no: [Rect, ...]}`` re-OCRs just those boxes, ``{page_no: None}`` the
    whole page. When omitted every page is OCR'd in full.
    """
    from .ocr import ocr_page_best, ocr_page_words

    report = VerificationReport()
    with pymupdf.open(path) as doc:
        pages = (sorted(rects_by_page) if rects_by_page is not None
                 else range(doc.page_count))
        for pno in pages:
            if pno >= doc.page_count:
                continue
            page = doc[pno]
            clips = rects_by_page[pno] if rects_by_page is not None else None
            words = []
            for clip in (clips or [None]):
                if clip is None:
                    # read the whole page the way a reader would: a copy that
                    # keeps the sheet's sideways rotation must not be OCR'd
                    # upside down or every glyph becomes a false pattern hit
                    rot = page.rotation
                    try:
                        words.extend(ocr_page_best(page, dpi=dpi, lang=lang)[0])
                    finally:
                        page.set_rotation(rot)
                else:
                    words.extend(ocr_page_words(page, dpi=dpi, lang=lang, clip=clip))
            for cell in cells_from_words(words):
                text = cell["text"]
                report.pattern_hits.update(_count_pattern_hits(text, source_vocab))
                for tok in set(_WORD_RE.findall(text)):
                    if PLACEHOLDER_RE.fullmatch(tok):
                        continue
                    cat = redacted_hashes.get(h(tok))
                    if cat and norm(tok) in unredacted_vocab:
                        cat = None
                    if not cat:
                        continue
                    report.leak_total += 1
                    report.leaks_by_category[cat] += 1
                    if len(report.masked_samples) < sample_limit:
                        report.masked_samples.append((cat, len(tok), _mask(tok)))
    return report
