"""PDF layout helpers: turn a page's words into gap-separated 'cells'.

Reports are tables: a label and its value share a line but sit far apart. Grouping
words by (block, line) and splitting on wide horizontal gaps gives us one cell per
table column, so redacting a value does not swallow the row next to it.
"""
from __future__ import annotations

from collections import defaultdict

DEFAULT_GAP = 16.0


def page_cells(page, gap_threshold: float = DEFAULT_GAP):
    """Return [{'words': [(x0,y0,x1,y1,text,...)], 'text': 'joined'}] for a page."""
    words = page.get_text("words")  # (x0,y0,x1,y1,word,block,line,wordno)
    by_line = defaultdict(list)
    for w in words:
        by_line[(w[5], w[6])].append(w)

    groups = []
    for _key, ws in sorted(by_line.items()):
        ws.sort(key=lambda w: (w[0], w[7]))
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
