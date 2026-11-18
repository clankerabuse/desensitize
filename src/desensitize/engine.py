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
    ocr_page_best,
    ocr_region_words,
    page_ink_fraction,
    strong_words,
    word_conf,
)
from .patterns import EMAIL_RE, SALUTATION_RE, h, norm, sensitive_tokens
from .verify import ocr_rescan, scan_copy

PLACEHOLDER_COLOR = (0.62, 0.05, 0.05)
HEADER_MARGIN_X = 85.0     # a label this far left is a section header
SAME_LINE_TOL = 0.35       # * label height
VALUE_BELOW_GAP = 70.0
BLOCK_GAP = 95.0          # hard stop for a section header's value block
BLOCK_LINE_GAP = 24.0     # once a block starts, its lines are densely stacked
MAX_SAME_LINE_VALUES = 60   # a wide table row is still one row
MAX_BLOCK_VALUES = 500      # a 60-row table under one header is still one block
LOW_CONF_LABEL = "UNCLEAR"  # placeholder for a word OCR was not confident about
INK_FLOOR = 0.0003         # below this a page is blank, not unreadable

# One coverage policy. This used to be a fast/default/full/paranoid ladder, but a
# level that skipped a pasted ID card because it covered 0.19% of the page was a
# level whose owner could not see the leak -- and the copy looked just as clean
# either way. So: read everything readable, then prove it on the finished copy.
POLICY = {
    "ocr_images": True,          # every picture on a text page, not just big ones
    "min_conf": 80.0,            # shaky OCR words become [UNCLEAR], never guesses
    "image_min_pt": (8.0, 4.0),  # icon-sized pictures included
    "image_min_src_px": 64,
    "image_min_area_frac": 0.0,
    "verify_deep": True,         # re-OCR the pixels that were touched
}

# Settings that can still be overridden per run (CLI flags / kwargs).
OVERRIDABLE = ("ocr_images", "min_conf", "image_min_pt", "image_min_src_px",
               "image_min_area_frac", "verify_deep")


def resolve_policy(**overrides) -> dict:
    """The coverage policy, with any explicit override applied on top."""
    unknown = set(overrides) - set(OVERRIDABLE)
    if unknown:
        raise ValueError(f"unknown coverage setting(s): {', '.join(sorted(unknown))}")
    cfg = dict(POLICY)
    for key, value in overrides.items():
        if value is not None:
            cfg[key] = value
    return cfg

_VOCAB_RE = re.compile(r"[A-Za-z0-9][\w'\u2019@.\-]*")

# A table-header word ("BALANCE", "STATUS") sitting to the right of another
# header label. No digits, so a masked value ("XXXX XXXX 4412") is not caught.
_HEADER_CELL_RE = re.compile(r"^[A-Z][A-Z /&.'()\-]{1,19}$")


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
    unreadable_pages: list[int] = field(default_factory=list)   # OCR found nothing

    def as_dict(self) -> dict:
        return {
            "file": self.source.name,
            "pages": self.pages,
            "output": str(self.output) if self.output else None,
            "mode": self.mode,
            "ocr_pages": self.ocr_pages,
            "image_regions_ocrd": self.image_regions,
            "unreadable_pages": self.unreadable_pages,
            "redactions_by_type": dict(self.counts),
        }


@dataclass
class RedactionResult:
    documents: list[DocumentResult]
    counts: Counter                       # aggregate, by category
    redacted_hashes: dict[str, str]       # digest -> category
    unredacted_vocab: set[str]            # generic words that survive
    verify_deep: bool = True              # did the pixel proof run?
    verifications: dict = field(default_factory=dict)  # name -> VerificationReport

    @property
    def clean(self) -> bool:
        """Clean means: nothing the detectors look for survived, *and* every
        page was actually read. A page nothing could be read from is not clean,
        it is unproven."""
        return (all(r.clean for r in self.verifications.values())
                and not any(d.unreadable_pages for d in self.documents))

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    @property
    def ocr_pages(self) -> int:
        return sum(d.ocr_pages for d in self.documents)


def _derotated(words, matrix):
    """Word boxes read off a turned render, moved into unrotated page space."""
    out = []
    for w in words:
        r = pymupdf.Rect(w[:4]) * matrix
        out.append((r.x0, r.y0, r.x1, r.y1) + tuple(w[4:]))
    return out


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
                 lang: str = DEFAULT_LANG, min_conf: float | None = None,
                 ocr_images: bool | None = None,
                 image_min_pt=None, image_min_src_px=None,
                 image_min_area_frac=None, verify_deep: bool | None = None):
        if ocr not in {"auto", "force", "off"}:
            raise ValueError("ocr must be one of: auto, force, off")
        cfg = resolve_policy(ocr_images=ocr_images, min_conf=min_conf,
                             image_min_pt=image_min_pt,
                             image_min_src_px=image_min_src_px,
                             image_min_area_frac=image_min_area_frac,
                             verify_deep=verify_deep)
        self.out_dir = Path(out_dir)
        self.names_file = names_file
        self.gap = gap
        self.ocr = ocr
        self.dpi = dpi
        self.lang = lang
        self.min_conf = cfg["min_conf"]
        self.ocr_images = cfg["ocr_images"]
        self.image_min_pt = cfg["image_min_pt"]
        self.image_min_src_px = cfg["image_min_src_px"]
        self.image_min_area_frac = cfg["image_min_area_frac"]
        self.verify_deep = cfg["verify_deep"]

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
            header_style = lab_x <= HEADER_MARGIN_X and not SALUTATION_RE.match(cell["text"])

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
                if _HEADER_CELL_RE.match(c["text"].strip()):
                    continue          # sibling header, not this label's value
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
        # A cue on the previous line of the same block still applies to this one:
        # "our records show date of birth" / "05/18/1973" is one sentence that
        # wrapping split into two cells.
        prefixes: dict[int, str] = {}
        by_block: dict = defaultdict(list)
        for cell in cells:
            by_block[cell["words"][0][5]].append(cell)
        for items in by_block.values():
            items.sort(key=lambda c: (c["words"][0][1], c["words"][0][0]))
            prev = ""
            for c in items:
                prefixes[id(c)] = prev[-90:]
                prev = c["text"]

        for cell in cells:
            prefix = prefixes.get(id(cell), "")
            full = f"{prefix} {cell['text']}" if prefix else cell["text"]
            off = len(full) - len(cell["text"])
            spans = [(max(0, s - off), e - off, lab)
                     for s, e, lab in detect_in_cell(full, known_names, name_freq,
                                                     ocr_mode=ocr_mode)
                     if e - off > 0]
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

    # -- objects that are not in the content stream ------------------------
    def _redact_string(self, text, known_names, name_freq, hashes, counts, vocab,
                       whole: bool = False):
        """Replace every detected span in a plain string; return (new, hits).

        `whole` is for short navigational strings -- a bookmark title, an
        annotation's subject. Replacement is all-or-nothing there: half a title
        ("Gideon Q. Moreau - SSN [SSN]") still names the person, and nobody needs
        the rest of a bookmark title to navigate.
        """
        if not text:
            return text, 0
        spans = detect_in_cell(text, known_names, name_freq)
        if not spans:
            return text, 0
        for start, end, label in spans:
            counts[label] += 1
            for tok in sensitive_tokens(text[start:end]):
                hashes.setdefault(h(tok), label)
        if whole:
            return "[REDACTED]", len(spans)
        out, pos = [], 0
        for start, end, label in spans:
            out.append(text[pos:start])
            out.append(f"[{label}]")
            pos = max(pos, end)
        out.append(text[pos:])
        return "".join(out), len(spans)

    def _scrub_objects(self, doc, known_names, name_freq, hashes, counts, vocab):
        """Annotations, form fields, outline titles and attached files.

        None of this lives in the page content stream: a copy can look perfectly
        redacted and still carry the SSN in a sticky note, a text field value, a
        bookmark title or an attachment.
        """
        for page in doc:
            try:
                annots = list(page.annots() or [])
            except Exception:
                annots = []
            for annot in annots:
                try:
                    info = dict(annot.info or {})
                except Exception:
                    continue
                changed = False
                for key in ("content", "subject", "title"):
                    new, hits = self._redact_string(info.get(key) or "", known_names,
                                                    name_freq, hashes, counts, vocab,
                                                    whole=(key != "content"))
                    if hits:
                        info[key] = new
                        changed = True
                if not changed:
                    continue
                try:
                    annot.set_info(**{k: info.get(k, "") for k in
                                      ("content", "subject", "title")})
                    annot.update()
                except Exception:
                    try:
                        page.delete_annot(annot)     # cannot rewrite it: drop it
                    except Exception:
                        pass

            try:
                widgets = list(page.widgets() or [])
            except Exception:
                widgets = []
            for widget in widgets:
                try:
                    value = widget.field_value or ""
                except Exception:
                    continue
                if not value.strip():
                    continue
                new, hits = self._redact_string(value, known_names, name_freq,
                                                hashes, counts, vocab)
                if not hits:
                    # The field *name* is a label: "ssn", "cardholder_name",
                    # "member_id". A one-off name in a field called "holder"
                    # has no other label to learn from.
                    label = label_only(re.sub(r"[_\-]+", " ",
                                              getattr(widget, "field_name", "") or ""))
                    if not label:
                        continue
                    for tok in sensitive_tokens(value):
                        hashes.setdefault(h(tok), label)
                    counts[label] += 1
                    new = f"[{label}]"
                try:
                    widget.field_value = new
                    widget.update()
                except Exception:
                    try:
                        page.delete_widget(widget)
                    except Exception:
                        pass

        try:
            toc = doc.get_toc() or []
        except Exception:
            toc = []
        new_toc, changed = [], False
        for level, title, page_no in toc:
            new, hits = self._redact_string(title, known_names, name_freq,
                                            hashes, counts, vocab, whole=True)
            changed = changed or bool(hits)
            new_toc.append([level, new, page_no])
        if changed:
            try:
                doc.set_toc(new_toc)
            except Exception:
                try:
                    doc.set_toc([])                 # unreadable titles: no outline
                except Exception:
                    pass

        # An attachment is a whole second document we cannot see into: drop it.
        try:
            names = list(doc.embfile_names() or [])
        except Exception:
            names = []
        for name in names:
            try:
                doc.embfile_del(name)
                counts["ATTACHMENT"] += 1
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
            #
            # Anything the visible box hides (a crop strip, a "gone" footer) is
            # read as well: the box is widened to the media box for the whole
            # pass and restored before the copy is saved. pdftotext reads the
            # strip; a reader does not -- so a copy that ignored it would leak to
            # exactly the tools this is meant to feed.
            widened: list[list] = []
            for doc in docs:
                pairs = []
                for page in doc:
                    try:
                        crop, media = pymupdf.Rect(page.cropbox), pymupdf.Rect(page.mediabox)
                        if crop != media:
                            pairs.append((page, crop))
                            page.set_cropbox(media)
                    except Exception:
                        continue
                widened.append(pairs)

            # A page OCR could not read at all, and a page with ink on it, is
            # not a clean page: it is an unproven one. Per document, so the run
            # can say which copy needs a human.
            unreadable: dict[int, list[int]] = {}

            plans: list[list[_PagePlan]] = []
            for doc_idx, doc in enumerate(docs):
                doc_plans = []
                # xrefs are only unique inside one document: a cache shared
                # across a batch hands file A's OCR words to file B's picture.
                image_cache: dict = {}   # (xref, w, h) -> (rect, words): logos repeat
                # what the *input* says, so the copy's OCR noise cannot be
                # mistaken for a residual value later
                src_tokens = [p.get_text("text") for p in doc]

                for pno, page in enumerate(doc):
                    use_ocr = self.ocr == "force" or (
                        self.ocr == "auto" and page_needs_ocr(page))
                    if use_ocr:
                        original_rotation = page.rotation
                        words, rotation = ocr_page_best(page, dpi=self.dpi,
                                                       lang=self.lang)
                        # Group into cells while the words still read normally --
                        # the clustering assumes horizontal lines -- then move the
                        # boxes into unrotated page space, which is the frame every
                        # redaction rectangle is measured in.
                        cells = cells_from_words(words, self.gap)
                        if rotation != original_rotation:
                            # one box per word, shared by the cells and the plan:
                            # the rebuild skips redacted words by identity, and a
                            # second copy of a tuple would smuggle the value back
                            # into the invisible text layer
                            moved = _derotated(words, page.derotation_matrix)
                            original = {id(w): nw for w, nw in zip(words, moved)}
                            for cell in cells:
                                cell["words"] = [original[id(w)] for w in cell["words"]]
                            words = moved
                        page.set_rotation(original_rotation)
                        if not strong_words(words) and page_ink_fraction(page) > INK_FLOOR:
                            unreadable.setdefault(doc_idx, []).append(pno)
                        src_tokens.extend(w[4] for w in words)
                        doc_plans.append(_PagePlan(cells=cells, ocr_mode=True, words=words))
                        continue

                    plan = _PagePlan(cells=page_cells(page, self.gap), ocr_mode=False)
                    if self.ocr_images:
                        # text page: look for pictures that can hide text of their own
                        regions = image_regions(page,
                                                min_pt=self.image_min_pt,
                                                min_src_px=self.image_min_src_px,
                                                min_area_frac=self.image_min_area_frac)
                        for idx, (rect, xref) in enumerate(regions):
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
            verifications: dict = {}

            for doc_idx, (src, doc, doc_plans) in enumerate(zip(paths, docs, plans)):
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

                self._scrub_objects(doc, known_names, name_freq, hashes, doc_counts, vocab)
                self._scrub_metadata(doc)

                # restore the visible box / rotation the page came with
                for page, undo in widened[doc_idx]:
                    try:
                        if isinstance(undo, tuple) and undo[0] == "rotation":
                            page.set_rotation(undo[1])
                        else:
                            page.set_cropbox(undo)
                    except Exception:
                        pass

                from .verify import tokens as _tokens
                source_vocab = _tokens(" ".join(src_tokens))
                dst = self.out_dir / safe_output_name(src)
                if not dry_run:
                    doc.save(dst, garbage=4, deflate=True, clean=True)
                    dst.chmod(0o600)

                    # Verify every copy: the text layer always, and the pixels
                    # that were OCR'd -- proof, not just consistency.
                    report = scan_copy(dst, hashes, vocab,
                                       source_vocab=source_vocab)
                    if self.verify_deep:
                        pixel_pages = {}
                        for pno, plan in enumerate(doc_plans):
                            if plan.ocr_mode:
                                pixel_pages[pno] = None            # whole page
                            elif plan.regions:
                                pixel_pages[pno] = [r for r, _w in plan.regions]
                        if pixel_pages:
                            report.merge(ocr_rescan(dst, hashes, vocab, lang=self.lang,
                                                    rects_by_page=pixel_pages,
                                                    source_vocab=source_vocab))
                    verifications[src.name] = report

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
                    unreadable_pages=unreadable.get(doc_idx, []),
                ))

            return RedactionResult(documents=documents, counts=counts,
                                   redacted_hashes=hashes, unredacted_vocab=vocab,
                                   verify_deep=self.verify_deep,
                                   verifications=verifications)
        finally:
            for doc in docs:
                doc.close()
