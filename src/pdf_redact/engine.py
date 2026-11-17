"""The redaction engine: plan marks per page, apply them, then re-read the result.

Two things matter for safety:

* **Destructive** redaction. `apply_redactions` deletes the glyphs from the
  content stream. Nothing is recoverable by copy-paste, text extraction or
  `pdftotext`.
* **Placeholders instead of blanks.** Every redacted span is replaced with a
  typed token (`[SSN]`, `[ADDRESS]`, ...) so the copy stays readable and the
  reason for each hole is obvious.

The engine returns counts, never values.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import pymupdf

from .detect import (
    build_name_freq,
    detect_in_cell,
    label_only,
    learn_names_from_labels,
    load_names,
)
from .layout import has_text_layer, page_cells, words_for_span
from .patterns import EMAIL_RE, h, norm, sensitive_tokens

PLACEHOLDER_COLOR = (0.62, 0.05, 0.05)
HEADER_MARGIN_X = 85.0     # a label this far left is a section header
SAME_LINE_TOL = 0.35       # * label height
VALUE_BELOW_GAP = 70.0
BLOCK_GAP = 95.0
MAX_SAME_LINE_VALUES = 10
MAX_BLOCK_VALUES = 20

_VOCAB_RE = re.compile(r"[A-Za-z0-9][\w'\u2019@.\-]*")


class NoTextLayerError(RuntimeError):
    """Raised for scanned PDFs: they need OCR before redaction can be trusted."""


@dataclass
class DocumentResult:
    source: Path
    pages: int
    output: Path | None
    counts: Counter = field(default_factory=Counter)


@dataclass
class RedactionResult:
    documents: list[DocumentResult]
    counts: Counter                       # aggregate, by category
    redacted_hashes: dict[str, str]       # digest -> category
    unredacted_vocab: set[str]            # generic words that survive

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def safe_output_name(path: Path) -> str:
    """Strip identifiers out of the filename too (account/report numbers leak)."""
    stem = EMAIL_RE.sub("redacted", path.stem)
    stem = re.sub(r"\d{4,}", "redacted", stem)
    stem = re.sub(r"[^\w \-.()]+", "_", stem).strip(" ._-")
    return (stem or "document") + ".pdf"


class Redactor:
    """Redacts one or more PDFs and writes copies to an output directory."""

    def __init__(self, out_dir: str | Path, names_file: str | Path | None = None,
                 gap: float = 16.0):
        self.out_dir = Path(out_dir)
        self.names_file = names_file
        self.gap = gap

    # -- planning ---------------------------------------------------------
    def _take(self, marks, hashes, counts, page_no, word_tuples, label):
        counts[label] += 1
        marks.append((page_no, [pymupdf.Rect(w[:4]) for w in word_tuples], label))
        for tok in sensitive_tokens(" ".join(w[4] for w in word_tuples)):
            hashes.setdefault(h(tok), label)

    def _plan_page(self, page, page_no, cells, known_names, name_freq,
                   marks, hashes, counts, vocab):
        # --- label-driven cells ------------------------------------------
        ordered = sorted(cells, key=lambda c: (c["words"][0][1], c["words"][0][0]))
        for cell in cells:
            lab = label_only(cell["text"])
            if not lab:
                continue
            lw = cell["words"][0]
            lab_y0, lab_y1, lab_x = lw[1], lw[3], lw[0]
            tol = max(1.5, (lab_y1 - lab_y0) * SAME_LINE_TOL)
            header_style = lab_x <= HEADER_MARGIN_X

            # values to the right on the same line ("Account Number  XXXX")
            taken = 0
            for c in ordered:
                if c is cell or not c["text"].strip():
                    continue
                w = c["words"][0]
                if abs(w[1] - lab_y0) > tol or w[0] <= lab_x:
                    continue
                if label_only(c["text"]):
                    continue
                self._take(marks, hashes, counts, page_no, c["words"], lab)
                taken += 1
                if taken >= MAX_SAME_LINE_VALUES:
                    break
            if taken:
                continue

            if not header_style:
                # one value line directly under the label
                for c in ordered:
                    if c is cell or not c["text"].strip():
                        continue
                    w = c["words"][0]
                    if not (-1 <= w[1] - lab_y1 <= VALUE_BELOW_GAP):
                        continue
                    if not (-6 <= w[0] - lab_x <= 45):
                        continue
                    if label_only(c["text"]):
                        break
                    self._take(marks, hashes, counts, page_no, c["words"], lab)
                continue

            # section header ("Names", "Employers"): take the whole value block
            start_y, last_y1, n = lab_y1, lab_y1, 0
            for c in ordered:
                w = c["words"][0]
                if c is cell or not c["text"].strip():
                    continue
                if w[1] <= start_y + 1:   # siblings share a line with the block
                    continue
                other = label_only(c["text"])
                if other:
                    # a new left-margin header ends this block; inner labels
                    # ("AKA", "Phone") do not
                    if w[0] <= HEADER_MARGIN_X and other != lab:
                        break
                    continue
                if w[1] - last_y1 > BLOCK_GAP:
                    break
                self._take(marks, hashes, counts, page_no, c["words"], lab)
                last_y1 = max(last_y1, c["words"][-1][3])
                n += 1
                if n >= MAX_BLOCK_VALUES:
                    break

        # --- span-driven cells -------------------------------------------
        for cell in cells:
            spans = detect_in_cell(cell["text"], known_names, name_freq)
            if not spans:
                vocab |= {norm(t) for t in _VOCAB_RE.findall(cell["text"])}
            else:
                pos = 0
                for start, end, _lab in spans:
                    vocab |= {norm(t) for t in _VOCAB_RE.findall(cell["text"][pos:start])}
                    pos = max(pos, end)
                vocab |= {norm(t) for t in _VOCAB_RE.findall(cell["text"][pos:])}

            for start, end, label in spans:
                words = words_for_span(cell["words"], cell["text"], start, end)
                if not words:
                    continue
                self._take(marks, hashes, counts, page_no, words, label)
                for tok in sensitive_tokens(cell["text"][start:end]):
                    hashes.setdefault(h(tok), label)

    # -- applying ---------------------------------------------------------
    @staticmethod
    def _apply_page(page, page_marks):
        for rects, _label in page_marks:
            for r in rects:
                page.add_redact_annot(r, fill=(1, 1, 1), cross_out=False)
        try:
            page.apply_redactions(images=pymupdf.PDF_REDACT_IMAGE_NONE,
                                  graphics=pymupdf.PDF_REDACT_LINE_ART_NONE,
                                  text=pymupdf.PDF_REDACT_TEXT_REMOVE)
        except Exception:  # older PyMuPDF builds: fewer knobs
            page.apply_redactions()

    @staticmethod
    def _draw_placeholders(page, page_marks):
        drawn = []
        for rects, label in page_marks:
            r = rects[0]
            if any(abs(r.x0 - px) < 14 and abs(r.y0 - py) < 4 for px, py in drawn):
                continue  # stacked cells: one placeholder per spot stays legible
            drawn.append((r.x0, r.y0))
            size = max(4.5, min(7.5, (rects[0].height or 8) * 0.72))
            try:
                page.insert_text((r.x0 + 0.6, r.y1 - 0.22 * size), f"[{label}]",
                                 fontsize=size, fontname="helv", color=PLACEHOLDER_COLOR)
            except Exception:
                pass

    @staticmethod
    def _scrub_metadata(doc):
        doc.set_metadata({"title": "", "author": "", "subject": "", "keywords": "",
                          "creator": "", "producer": ""})
        try:
            doc.del_xml_metadata()
        except Exception:
            pass

    # -- public API -------------------------------------------------------
    def redact(self, paths, dry_run: bool = False, debug_marks: bool = False) -> RedactionResult:
        paths = [Path(p) for p in paths]
        for p in paths:
            if not p.is_file():
                raise FileNotFoundError(p)

        docs = [pymupdf.open(p) for p in paths]
        try:
            for p, doc in zip(paths, docs):
                if not has_text_layer(doc):
                    raise NoTextLayerError(p.name)

            known_names = load_names(self.names_file) | learn_names_from_labels(docs)
            name_freq = build_name_freq(docs)

            if not dry_run:
                self.out_dir.mkdir(parents=True, exist_ok=True)
                self.out_dir.chmod(0o700)

            counts: Counter = Counter()
            hashes: dict[str, str] = {}
            vocab: set[str] = set()
            documents: list[DocumentResult] = []

            for src, doc in zip(paths, docs):
                doc_counts: Counter = Counter()
                marks = []  # (page_no, [Rect], label)

                for pno, page in enumerate(doc):
                    cells = page_cells(page, self.gap)
                    self._plan_page(page, pno, cells, known_names, name_freq,
                                    marks, hashes, doc_counts, vocab)

                if debug_marks:
                    for pno, rects, label in marks:
                        print(f"   mark p{pno + 1:>2} {label:<9} y={rects[0].y0:6.1f} "
                              f"x={rects[0].x0:6.1f} words={len(rects)} "
                              f"w={rects[0].width:.0f} h={rects[0].height:.0f}")

                by_page = defaultdict(list)
                for pno, rects, label in marks:
                    by_page[pno].append((rects, label))
                for pno, page in enumerate(doc):
                    page_marks = by_page.get(pno, [])
                    if not page_marks:
                        continue
                    self._apply_page(page, page_marks)
                    self._draw_placeholders(page, page_marks)

                self._scrub_metadata(doc)

                dst = self.out_dir / safe_output_name(src)
                if not dry_run:
                    doc.save(dst, garbage=4, deflate=True, clean=True)
                    dst.chmod(0o600)

                counts.update(doc_counts)
                documents.append(DocumentResult(
                    source=src,
                    pages=doc.page_count,
                    output=None if dry_run else dst,
                    counts=doc_counts,
                ))

            return RedactionResult(documents=documents, counts=counts,
                                   redacted_hashes=hashes, unredacted_vocab=vocab)
        finally:
            for doc in docs:
                doc.close()
