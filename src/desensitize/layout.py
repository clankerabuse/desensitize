"""PDF layout helpers: turn a page's words into gap-separated 'cells'.

Reports are tables: a label and its value share a line but sit far apart. Grouping
words by (block, line) and splitting on wide horizontal gaps gives us one cell per
table column, so redacting a value does not swallow the row next to it.
"""
from __future__ import annotations

from collections import defaultdict

import pymupdf

DEFAULT_GAP = 16.0

# An embedded image is worth OCR-ing when it is big enough to hold text that
# matters. Logos, icons, rules and 5x5 spacer tiles are not: skipping them keeps
# a 25-page report from paying for 26 pointless tesseract runs.
IMAGE_MIN_PT = (40.0, 12.0)      # rendered width, height in points
IMAGE_MIN_SRC_PX = 5000          # source pixels (width * height)
IMAGE_MIN_AREA_FRAC = 0.005      # share of the page area


def page_cells(page, gap_threshold: float = DEFAULT_GAP):
    """Return [{'words': [(x0,y0,x1,y1,text,...)], 'text': 'joined'}] for a page."""
    return cells_from_words(page.get_text("words"), gap_threshold)


def cells_from_words(words, gap_threshold: float = DEFAULT_GAP):
    """Same grouping, for words that came from OCR instead of the text layer.

    Tesseract's line numbers are not reliable enough to group on: two halves of
    one visual line ("... DOB September 13, 1965") routinely land in different
    blocks with a 0.2 pt baseline difference. So lines are clustered by their
    y centre, and a group is only eligible for merging when its box is a normal
    single-line height (rotated runs and multi-line blocks keep to themselves).
    """
    by_line = defaultdict(list)
    for w in words:
        by_line[(w[5], w[6])].append(w)

    lines = []
    for _key, ws in by_line.items():
        ws.sort(key=lambda w: (w[0], w[7]))
        y0 = min(w[1] for w in ws)
        y1 = max(w[3] for w in ws)
        lines.append({"ws": ws, "y0": y0, "y1": y1})
    lines.sort(key=lambda L: (L["y0"], L["ws"][0][0]))

    merged: list[dict] = []
    for line in lines:
        if merged:
            prev = merged[-1]
            h_prev, h_line = prev["y1"] - prev["y0"], line["y1"] - line["y0"]
            mid_prev = (prev["y0"] + prev["y1"]) / 2
            mid_line = (line["y0"] + line["y1"]) / 2
            if (abs(mid_prev - mid_line) <= 2.0 and 3.0 <= h_prev <= 40
                    and 3.0 <= h_line <= 40):
                prev["ws"] = prev["ws"] + line["ws"]
                prev["y0"] = min(prev["y0"], line["y0"])
                prev["y1"] = max(prev["y1"], line["y1"])
                continue
        merged.append(dict(line))

    groups = []
    for line in merged:
        ws = sorted(line["ws"], key=lambda w: (w[0], w[7]))
        cur, prev_x1 = [], None
        for w in ws:
            if cur and prev_x1 is not None and (w[0] - prev_x1) > gap_threshold:
                groups.append(cur)
                cur = []
            cur.append(w)
            prev_x1 = w[2]
        if cur:
            groups.append(cur)

    return [{"words": ws, "text": " ".join(w[4] for w in ws)} for ws in groups]


def words_for_span(cell_words, text: str, start: int, end: int):
    """Map a char span in the joined cell text back to its word tuples."""
    picked, pos = [], 0
    for w in cell_words:
        wlen = len(w[4])
        wstart, wend = pos, pos + wlen
        if wend > start and wstart < end:
            picked.append(w)
        pos = wend + 1  # words were joined with a single space
    return picked


def has_text_layer(doc, min_chars: int = 50) -> bool:
    """True when the document carries extractable text (not a pure scan)."""
    return len("".join(p.get_text("text") for p in doc).strip()) >= min_chars


def image_regions(page, min_pt=IMAGE_MIN_PT, min_src_px: int = IMAGE_MIN_SRC_PX,
                  min_area_frac: float = IMAGE_MIN_AREA_FRAC):
    """Embedded images big enough to carry text: [(bbox, xref)], deduplicated.

    A PDF can hide text in a picture on an otherwise-textual page (a screenshot of
    a statement, a scanned receipt pasted into a form). `page.get_image_info()`
    tells us where those pictures are, cheaply, before any OCR runs.
    """
    regions, seen = [], set()
    page_area = abs(page.rect.width * page.rect.height) or 1.0
    try:
        infos = page.get_image_info(xrefs=True)
    except Exception:
        return regions

    for info in infos:
        bbox = pymupdf.Rect(info["bbox"]) & page.rect
        if bbox.is_empty or bbox.is_infinite:
            continue  # fully off-page or degenerate
        if bbox.width < min_pt[0] or bbox.height < min_pt[1]:
            continue
        if info.get("width", 0) * info.get("height", 0) < min_src_px:
            continue
        if bbox.width * bbox.height < page_area * min_area_frac:
            continue
        key = (round(bbox.x0, 1), round(bbox.y0, 1),
               round(bbox.width, 1), round(bbox.height, 1), info.get("xref"))
        if key in seen:
            continue
        seen.add(key)
        regions.append((bbox, info.get("xref")))
    return regions


def page_needs_ocr(page, min_words: int = 5) -> bool:
    """Per-page test: a page with almost no words is a scan (or an image page)."""
    try:
        return len(page.get_text("words")) < min_words
    except Exception:
        return True
