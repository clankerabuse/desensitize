"""The redaction engine: plan marks per page, apply them, then re-read the result.

Two things matter for safety:

* **Destructive** redaction. On a text page `apply_redactions` deletes the glyphs
  from the content stream. On an OCR page it *burns the pixels*
  (`PDF_REDACT_IMAGE_PIXELS`), because for a scan the image **is** the document.
  Editing only an OCR text layer while leaving the picture intact is the classic
  fake redaction -- the data is still visible, and any OCR reads it straight back.
* **Placeholders instead of blanks.** Every redacted span is replaced with a typed
  token (`[SSN]`, `[ADDRESS]`, ...) so the copy stays readable; scanned pages also
  get a freshly written invisible text layer containing only the words we kept, so
  the copy still extracts as text without relying on OCR round-tripping.

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
from .layout import (
    cells_from_words,
    has_text_layer,
    image_regions,
    page_cells,
    page_needs_ocr,
    words_for_span,
)
from .ocr import (
    DEFAULT_DPI,
    DEFAULT_LANG,
    DEFAULT_MIN_CONF,
    ocr_page_words,
    ocr_region_words,
    word_conf,
)
from .patterns import EMAIL_RE, h, norm, sensitive_tokens

PLACEHOLDER_COLOR = (0.62, 0.05, 0.05)
HEADER_MARGIN_X = 85.0     # a label this far left is a section header
SAME_LINE_TOL = 0.35       # * label height
VALUE_BELOW_GAP = 70.0
BLOCK_GAP = 95.0          # hard stop for a section header's value block
BLOCK_LINE_GAP = 24.0     # once a block starts, its lines are densely stacked
MAX_SAME_LINE_VALUES = 10
MAX_BLOCK_VALUES = 20
LOW_CONF_LABEL = "UNCLEAR"  # placeholder for a word OCR was not confident about

_VOCAB_RE = re.compile(r"[A-Za-z0-9][\w'\u2019@.\-]*")


class NoTextLayerError(RuntimeError):
    """Raised for scanned PDFs when OCR is disabled: refuse rather than fake it."""


@dataclass
class DocumentResult:
    source: Path
    pages: int
    output: Path | None
    counts: Counter = field(default_factory=Counter)
    ocr_pages: int = 0
    image_regions: int = 0      # embedded pictures that were OCR'd
    mode: str = "text"          # text | ocr | mixed

    def as_dict(self) -> dict:
        return {
            "file": self.source.name,
            "pages": self.pages,
            "output": str(self.output) if self.output else None,
            "mode": self.mode,
            "ocr_pages": self.ocr_pages,
            "image_regions_ocrd": self.image_regions,
            "redactions_by_type": dict(self.counts),
        }


@dataclass
class RedactionResult:
    documents: list[DocumentResult]
    counts: Counter                       # aggregate, by category
    redacted_hashes: dict[str, str]       # digest -> category
    unredacted_vocab: set[str]            # generic words that survive

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    @property
    def ocr_pages(self) -> int:
        return sum(d.ocr_pages for d in self.documents)


def safe_output_name(path: Path) -> str:
    """Strip identifiers out of the filename too (account/report numbers leak)."""
    stem = EMAIL_RE.sub("redacted", path.stem)
    stem = re.sub(r"\d{4,}", "redacted", stem)
    stem = re.sub(r"[^\w \-.()]+", "_", stem).strip(" ._-")
    return (stem or "document") + ".pdf"


@dataclass
class _PagePlan:
    """Everything decided for one page before anything is written."""
    cells: list
    ocr_mode: bool
    words: list | None = None     # OCR words, whole page (scans)
    regions: list = field(default_factory=list)   # (bbox, words) for embedded images


class Redactor:
    """Redacts one or more PDFs and writes copies to an output directory.

    ocr:
        "auto"  -- OCR only the pages that carry no text layer (default)
        "force" -- OCR every page, even textual ones (scan with a junk layer)
        "off"   -- refuse scanned input (text-layer-only behaviour)
    """

    def __init__(self, out_dir: str | Path, names_file: str | Path | None = None,
                 gap: float = 16.0, ocr: str = "auto", dpi: int = DEFAULT_DPI,
                 lang: str = DEFAULT_LANG, min_conf: float = DEFAULT_MIN_CONF,
                 ocr_images: bool = True):
        if ocr not in {"auto", "force", "off"}:
            raise ValueError("ocr must be one of: auto, force, off")
        self.out_dir = Path(out_dir)
        self.names_file = names_file
        self.gap = gap
        self.ocr = ocr
        self.dpi = dpi
        self.lang = lang
        self.min_conf = min_conf
        self.ocr_images = ocr_images

    # -- planning ---------------------------------------------------------
    def _take(self, marks, hashes, counts, page_no, word_tuples, label):
        counts[label] += 1
        marks.append((page_no, list(word_tuples), label))
        for tok in sensitive_tokens(" ".join(w[4] for w in word_tuples)):
            hashes.setdefault(h(tok), label)

    def _plan_page(self, page_no, cells, known_names, name_freq, ocr_mode,
                   marks, hashes, counts, vocab):
        # --- uncertain OCR words fail closed -----------------------------
        if ocr_mode:
            for cell in cells:
                for w in cell["words"]:
                    if word_conf(w) < self.min_conf and (re.search(r"\d", w[4]) or len(w[4]) >= 3):
                        self._take(marks, hashes, counts, page_no, [w], LOW_CONF_LABEL)

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
            first_line = True
            for c in ordered:
                w = c["words"][0]
                if c is cell or not c["text"].strip():
                    continue
                if w[1] <= start_y + 1:   # siblings share a line with the block
                    continue
                other = label_only(c["text"])
                if other:
                    # A label of a different family ends the block. Same-family
                    # sub-labels ("AKA" under "Names", "Cellular" under "Phone
                    # Numbers") do not -- and neither does indentation, or a
                    # section header would swallow the next account table.
                    if other != lab:
                        break
                    continue
                gap = w[1] - last_y1
                if gap > BLOCK_GAP:
                    break
                # The first value line may sit well below its header, but the
                # rest of a block is densely stacked. A big jump means a new
                # section (e.g. the account table) and must end the block.
                if not first_line and gap > BLOCK_LINE_GAP:
                    break
                self._take(marks, hashes, counts, page_no, c["words"], lab)
                last_y1 = max(last_y1, c["words"][-1][3])
                first_line = False
                n += 1
                if n >= MAX_BLOCK_VALUES:
                    break

        # --- span-driven cells -------------------------------------------
        for cell in cells:
            spans = detect_in_cell(cell["text"], known_names, name_freq, ocr_mode=ocr_mode)
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
    def _apply_page(page, page_marks, smear_images: bool):
        for words, _label in page_marks:
            for w in words:
                page.add_redact_annot(pymupdf.Rect(w[:4]), fill=(1, 1, 1), cross_out=False)
        kwargs = dict(graphics=pymupdf.PDF_REDACT_LINE_ART_NONE,
                      text=pymupdf.PDF_REDACT_TEXT_REMOVE)
        # a scanned page has no glyphs to delete: burn the pixels instead
        kwargs["images"] = (pymupdf.PDF_REDACT_IMAGE_PIXELS if smear_images
                            else pymupdf.PDF_REDACT_IMAGE_NONE)
        try:
            page.apply_redactions(**kwargs)
        except Exception:  # older PyMuPDF builds: fewer knobs
            page.apply_redactions()

    @staticmethod
    def _draw_placeholders(page, page_marks):
        drawn = []
        for words, label in page_marks:
            r = pymupdf.Rect(words[0][:4])
            if any(abs(r.x0 - px) < 14 and abs(r.y0 - py) < 4 for px, py in drawn):
                continue  # stacked cells: one placeholder per spot stays legible
            drawn.append((r.x0, r.y0))
            size = max(4.5, min(7.5, (r.height or 8) * 0.72))
            try:
                page.insert_text((r.x0 + 0.6, r.y1 - 0.22 * size), f"[{label}]",
                                 fontsize=size, fontname="helv", color=PLACEHOLDER_COLOR)
            except Exception:
                pass

    @staticmethod
    def _rebuild_text_layer(page, words, redacted_ids):
        """Write an invisible text layer holding only the words we kept."""
        for w in words:
            if id(w) in redacted_ids:
                continue
            height = max(4.0, min(16.0, (w[3] - w[1]) * 0.9))
            try:
                page.insert_text((w[0], w[3] - 0.22 * height), w[4], fontsize=height,
                                 fontname="helv", color=(0, 0, 0), render_mode=3)
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
            if self.ocr == "off":
                for p, doc in zip(paths, docs):
                    if not has_text_layer(doc):
                        raise NoTextLayerError(
                            f"{p.name}: no text layer (scanned PDF) and OCR is disabled")

            # Pass 1: decide the mode per page and (where needed) OCR once. The
            # cells are cached so learning, detection and the text-layer rebuild
            # all work from the same OCR output.
            plans: list[list[_PagePlan]] = []
            image_cache: dict = {}   # (xref, w, h) -> (rect, words): logos repeat
            for doc in docs:
                doc_plans = []
                for page in doc:
                    use_ocr = self.ocr == "force" or (
                        self.ocr == "auto" and page_needs_ocr(page))
                    if use_ocr:
                        words = ocr_page_words(page, dpi=self.dpi, lang=self.lang)
                        doc_plans.append(_PagePlan(cells=cells_from_words(words, self.gap),
                                                   ocr_mode=True, words=words))
                        continue

                    plan = _PagePlan(cells=page_cells(page, self.gap), ocr_mode=False)
                    if self.ocr_images:
                        # text page: look for pictures that can hide text of their own
                        for idx, (rect, xref) in enumerate(image_regions(page)):
                            key = (xref, round(rect.width, 1), round(rect.height, 1))
                            cached = image_cache.get(key) if xref else None
                            if cached:
                                base, cached_words = cached
                                dx, dy = rect.x0 - base.x0, rect.y0 - base.y0
                                words = [(w[0] + dx, w[1] + dy, w[2] + dx, w[3] + dy,
                                          *w[4:]) for w in cached_words]
                            else:
                                words = ocr_region_words(page, rect, dpi=self.dpi,
                                                         lang=self.lang,
                                                         block_namespace=idx + 1)
                                if xref and words:
                                    image_cache[key] = (rect, words)
                            if not words:
                                continue
                            plan.regions.append((rect, words))
                            plan.cells.extend(cells_from_words(words, self.gap))
                    doc_plans.append(plan)
                plans.append(doc_plans)

            # Pass 2: name learning across every page of every input.
            all_cells = [p.cells for doc_plans in plans for p in doc_plans]
            known_names = load_names(self.names_file) | learn_names_from_labels(all_cells)
            name_freq = build_name_freq(all_cells)

            if not dry_run:
                self.out_dir.mkdir(parents=True, exist_ok=True)
                self.out_dir.chmod(0o700)

            counts: Counter = Counter()
            hashes: dict[str, str] = {}
            vocab: set[str] = set()
            documents: list[DocumentResult] = []

            for src, doc, doc_plans in zip(paths, docs, plans):
                doc_counts: Counter = Counter()
                marks = []          # (page_no, [word tuples], label)

                for pno, plan in enumerate(doc_plans):
                    self._plan_page(pno, plan.cells, known_names, name_freq, plan.ocr_mode,
                                    marks, hashes, doc_counts, vocab)

                if debug_marks:
                    for pno, words, label in marks:
                        r = pymupdf.Rect(words[0][:4])
                        print(f"   mark p{pno + 1:>2} {label:<9} y={r.y0:6.1f} x={r.x0:6.1f} "
                              f"words={len(words)} w={r.width:.0f} h={r.height:.0f}")

                by_page = defaultdict(list)
                for pno, words, label in marks:
                    by_page[pno].append((words, label))

                for pno, page in enumerate(doc):
                    page_marks = by_page.get(pno, [])
                    plan = doc_plans[pno]
                    # words that came from pixels (whole page or an image region)
                    pixel_words = list(plan.words or [])
                    for _rect, words in plan.regions:
                        pixel_words.extend(words)
                    if not page_marks:
                        # nothing to redact, but OCR'd pixels still need a text layer
                        if pixel_words:
                            self._rebuild_text_layer(page, pixel_words, set())
                        continue
                    # smearing is required whenever the redacted words live in an
                    # image: deleting a text layer leaves the picture untouched
                    self._apply_page(page, page_marks,
                                     smear_images=plan.ocr_mode or bool(plan.regions))
                    self._draw_placeholders(page, page_marks)
                    if pixel_words:
                        redacted_ids = {id(w) for words, _l in page_marks for w in words}
                        self._rebuild_text_layer(page, pixel_words, redacted_ids)

                self._scrub_metadata(doc)

                dst = self.out_dir / safe_output_name(src)
                if not dry_run:
                    doc.save(dst, garbage=4, deflate=True, clean=True)
                    dst.chmod(0o600)

                ocr_pages = sum(1 for p in doc_plans if p.ocr_mode)
                mode = ("ocr" if ocr_pages == doc.page_count
                        else "mixed" if ocr_pages else "text")
                counts.update(doc_counts)
                documents.append(DocumentResult(
                    source=src,
                    pages=doc.page_count,
                    output=None if dry_run else dst,
                    counts=doc_counts,
                    ocr_pages=ocr_pages,
                    image_regions=sum(len(p.regions) for p in doc_plans),
                    mode=mode,
                ))

            return RedactionResult(documents=documents, counts=counts,
                                   redacted_hashes=hashes, unredacted_vocab=vocab)
        finally:
            for doc in docs:
                doc.close()
