"""Decide what to redact inside a cell of text.

`detect_in_cell` is the single entry point: give it a cell's text plus the
learned name vocabulary and it returns non-overlapping (start, end, label)
spans. It combines, in priority order:

1. "Label: value" prefixes  -- value runs to the end of the cell
2. Value regexes            -- SSN, email, phone, address, ZIP, long IDs
3. DOB context              -- dates/years on a line that mentions birth
4. Learned names            -- bare mentions of a name seen in a labelled field
5. Whole-cell address lines -- keeps city/state fragments from surviving
6. Person-name candidates   -- capitalised runs, minus company vocabulary
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from .patterns import (
    ADDRESS_FRAG_RE,
    ADDRESS_RE,
    DATE_RE,
    DOB_CTX_RE,
    GAP_OK_RE,
    LABEL_PREFIX_RES,
    LABEL_RES,
    NAME_STOP,
    OCR_PATTERNS,
    ORG_LABEL_CONTEXT_RE,
    ORG_MARKERS,
    PATTERNS,
    TOKEN_RE,
    YEAR_RE,
    ZIP_RE,
    digit_count,
)


def label_only(text: str):
    """Return the label family if the cell is nothing but a field label."""
    variants = (text, text.replace("(s)", "s").replace("(es)", "s"))
    for lab, pats in LABEL_RES:
        for _pat, rx in pats:
            if any(rx.match(v) for v in variants):
                return lab
    return None


def merge_spans(spans):
    """Sort and coalesce overlapping spans, keeping the first (earliest) label."""
    if not spans:
        return []
    spans = sorted(spans, key=lambda s: (s[0], -s[1]))
    merged = [list(spans[0])]
    for start, end, lab in spans[1:]:
        if start < merged[-1][1]:
            if end > merged[-1][1]:
                merged[-1][1] = end
        else:
            merged.append([start, end, lab])
    return [tuple(m) for m in merged]


def name_spans(text: str, known_names: set[str], name_freq: Counter):
    """Conservative person-name detection.

    A candidate is 2-4 consecutive capitalised tokens joined only by spaces or
    punctuation. It is rejected when any token is organisation vocabulary (so
    creditor names stay readable) or when every token is generic report
    vocabulary. It is accepted when a token was learned from a labelled name
    field, or when the same 2/3-token run occurs at least twice in the inputs
    (a consumer's name repeats in headers and footers; a random proper noun does
    not).
    """
    toks = [(m.group(0), m.start(), m.end()) for m in TOKEN_RE.finditer(text)]
    spans = []
    i, n = 0, len(toks)
    while i < n:
        j = i
        while j + 1 < n and GAP_OK_RE.match(text[toks[j][2]:toks[j + 1][1]]):
            j += 1
        cap = []
        for t in toks[i:j + 1]:  # leading capitalised stretch only
            if t[0][:1].isupper() or t[0].isupper():
                cap.append(t)
            else:
                break

        accepted = []
        # Longest window first, then shorter ones inside it, so a name followed
        # by more proper nouns ("... - Report Date") still matches.
        for size in range(min(len(cap), 4), 1, -1):
            for s in range(0, len(cap) - size + 1):
                win = cap[s:s + size]
                lower = [x[0].lower().strip(".") for x in win]
                if any(w in ORG_MARKERS for w in lower):
                    continue
                if all(w in NAME_STOP for w in lower):
                    continue
                if not [w for w in lower if w not in NAME_STOP and len(w) >= 2]:
                    continue
                key2 = " ".join(lower[:2])
                key3 = " ".join(lower[:3])
                if not (any(w in known_names for w in lower)
                        or name_freq.get(key2, 0) >= 2
                        or name_freq.get(key3, 0) >= 2):
                    continue
                start, end = win[0][1], win[-1][2]
                if any(start < a[1] and end > a[0] for a in accepted):
                    continue
                accepted.append((start, end))
                spans.append((start, end, "NAME"))
        i = j + 1
    return spans


def detect_in_cell(text: str, known_names: set[str], name_freq: Counter,
                   ocr_mode: bool = False):
    """Return non-overlapping (start, end, label) spans to redact in this cell.

    `ocr_mode` adds detectors that tolerate tesseract's glyph confusions
    (0/O, 1/I/l, 5/S, 8/B). Those variants demand a minimum number of real
    digits before they fire, so ordinary words cannot match.
    """
    spans = []

    # 1. "Label: value" -- checked first so its label wins over a generic pattern
    for lab, pats in LABEL_PREFIX_RES:
        for _pat, rx in pats:
            for m in rx.finditer(text):
                if lab == "NAME":
                    before = text[max(0, m.start() - 30):m.start()].lower()
                    if ORG_LABEL_CONTEXT_RE.search(before):
                        continue
                start = m.end()
                while start < len(text) and text[start] in " \t:.-":
                    start += 1
                if start < len(text):
                    spans.append((start, len(text), lab))

    # 2. value regexes
    for label, rx in PATTERNS:
        for m in rx.finditer(text):
            if m.end() > m.start():
                spans.append((m.start(), m.end(), label))

    if ocr_mode:
        for label, rx, min_digits in OCR_PATTERNS:
            for m in rx.finditer(text):
                if digit_count(m.group(0)) >= min_digits:
                    spans.append((m.start(), m.end(), label))

    # 3. contextual date of birth
    if DOB_CTX_RE.search(text):
        for m in DATE_RE.finditer(text):
            spans.append((m.start(), m.end(), "DOB"))
        for m in YEAR_RE.finditer(text):
            spans.append((m.start(), m.end(), "DOB"))

    # 4. bare mentions of a name learned from a labelled field
    for m in TOKEN_RE.finditer(text):
        tok = m.group(0).lower().strip(".")
        if len(tok) >= 3 and tok in known_names:
            spans.append((m.start(), m.end(), "NAME"))

    # 5. address-ish cells are dense: redact the whole cell so no city/state/
    #    street fragment survives on its own
    if ADDRESS_RE.search(text):
        spans.append((0, len(text), "ADDRESS"))
    elif ZIP_RE.search(text) and len(text) <= 40 and _has_state_abbr(text):
        spans.append((0, len(text), "ADDRESS"))
    elif ADDRESS_FRAG_RE.match(text.strip()) and _has_street_word(text):
        spans.append((0, len(text), "ADDRESS"))

    # 6. person-name candidates
    spans.extend(name_spans(text, known_names, name_freq))

    return merge_spans(spans)


def _has_state_abbr(text: str) -> bool:
    import re as _re
    return bool(_re.search(r"\b[A-Z]{2}\b", text))


def _has_street_word(text: str) -> bool:
    return any(t[:1].isupper() and len(t) >= 4 and t.lower() not in NAME_STOP
               for t in TOKEN_RE.findall(text))


# --------------------------------------------------------------------------
# Learning pass: names and their cross-document frequency.
# --------------------------------------------------------------------------
def learn_names_from_labels(cell_lists) -> set[str]:
    """Harvest name tokens from explicitly labelled name fields, so later bare
    mentions (headers, footers, "Wexington, Z.") are caught too.

    `cell_lists` is one list of cells per page (text or OCR), so scanned identity
    blocks teach the vocabulary just like textual ones.
    """
    learned: set[str] = set()

    def harvest(text: str) -> None:
        for tok in TOKEN_RE.findall(text):
            w = tok.lower().strip(".")
            if len(w) >= 3 and w not in NAME_STOP and w not in ORG_MARKERS:
                learned.add(w)

    for cells in cell_lists:
        for cell in cells:
            w0 = cell["words"][0]
            if label_only(cell["text"]) == "NAME":
                # value cells sit on the same line to the right, or in the
                # block directly underneath the label
                for c in cells:
                    if c is cell or not c["text"].strip():
                        continue
                    w = c["words"][0]
                    same = abs(w[1] - w0[1]) <= 2 and w[0] > w0[0]
                    below = (-1 <= w[1] - w0[3] <= 70) and (-6 <= w[0] - w0[0] <= 300)
                    if (same or below) and not label_only(c["text"]):
                        harvest(c["text"])
                continue
            for lab, pats in LABEL_PREFIX_RES:
                if lab != "NAME":
                    continue
                for _pat, rx in pats:
                    m = rx.search(cell["text"])
                    if m:
                        harvest(cell["text"][m.end():])
                        break
    return learned


def build_name_freq(cell_lists) -> Counter:
    """Count capitalised 2/3-token runs across all inputs (cross-document)."""
    freq: Counter = Counter()
    for cells in cell_lists:
        for cell in cells:
            text = cell["text"]
            toks = [(m.group(0), m.start(), m.end()) for m in TOKEN_RE.finditer(text)]
            i = 0
            while i < len(toks):
                j = i
                while j + 1 < len(toks) and GAP_OK_RE.match(text[toks[j][2]:toks[j + 1][1]]):
                    j += 1
                caprun = []
                for t in toks[i:j + 1]:
                    if t[0][:1].isupper() or t[0].isupper():
                        caprun.append(t)
                    else:
                        break
                if len(caprun) >= 2:
                    lower = [t[0].lower().strip(".") for t in caprun]
                    for k in (2, 3):
                        for s in range(0, len(lower) - k + 1):
                            win = lower[s:s + k]
                            if any(w in ORG_MARKERS for w in win):
                                continue
                            if all(w in NAME_STOP for w in win):
                                continue
                            if not [w for w in win if w not in NAME_STOP and len(w) >= 2]:
                                continue
                            freq[" ".join(win)] += 1
                i = max(j + 1, i + 1)
    return freq


def load_names(path) -> set[str]:
    """Read an optional allowlist-of-names file (one name per line)."""
    names: set[str] = set()
    if not path:
        return names
    for line in Path(path).read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for tok in TOKEN_RE.findall(line):
            names.add(tok.lower().strip("."))
    return names
