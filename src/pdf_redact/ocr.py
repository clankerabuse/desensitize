"""OCR for pages that have no text layer.

Tesseract is invoked as a **local** process: no API calls, no uploads, the language
model is a file in `/usr/share/tessdata`. (`unshare -rn tesseract ...` works, i.e.
the pipeline needs no network at all.)

Words come back in the same tuple shape PyMuPDF uses for native text --
`(x0, y0, x1, y1, text, block, line, word_no)` -- with the tesseract confidence
appended as field 8, so every downstream detector works unchanged. Boxes are
scaled from pixels into PDF points.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from functools import lru_cache
from pathlib import Path

DEFAULT_DPI = 300
DEFAULT_LANG = "eng"
DEFAULT_MIN_CONF = 60.0


class OcrUnavailableError(RuntimeError):
    """Tesseract is not installed (or the requested language pack is missing)."""


def _exe() -> str:
    """Path to the local tesseract binary, or a clear error."""
    exe = shutil.which("tesseract")
    if not exe:
        raise OcrUnavailableError(
            "tesseract not found on PATH -- install it "
            "(Arch: pacman -S tesseract tesseract-data-eng, Debian: apt install tesseract-ocr)")
    return exe


@lru_cache(maxsize=1)
def tesseract_version() -> str:
    out = subprocess.run([_exe(), "--version"], capture_output=True, text=True)
    return (out.stdout or out.stderr).splitlines()[0].strip()


def available_languages() -> set[str]:
    out = subprocess.run([_exe(), "--list-langs"], capture_output=True, text=True)
    return {ln.strip() for ln in (out.stdout or "").splitlines()[1:] if ln.strip()}


def page_has_ocr_text(page, min_words: int = 5) -> bool:
    """True when the page already carries enough real text to skip OCR."""
    try:
        return len(page.get_text("words")) >= min_words
    except Exception:
        return False


def ocr_page_words(page, dpi: int = DEFAULT_DPI, lang: str = DEFAULT_LANG, clip=None):
    """OCR one page, or just `clip` of it. Word tuples carry confidence in field 8.

    Coordinates are absolute page points in both cases, so callers can lay
    redaction rectangles down without knowing which image a word came from.

    Raises OcrUnavailableError when tesseract or the language pack is missing, so
    the caller can fail loudly instead of silently producing an unredacted copy.
    """
    exe = _exe()          # raises if tesseract is absent
    langs = available_languages()
    if langs and lang not in langs:
        raise OcrUnavailableError(
            f"tesseract language '{lang}' not installed (have: {', '.join(sorted(langs))})")

    scale = dpi / 72.0          # pixels per point
    with tempfile.TemporaryDirectory(prefix="pdf-redact-ocr-") as tmp:
        img = Path(tmp) / "page.png"
        pix = page.get_pixmap(dpi=dpi, alpha=False, clip=clip)
        pix.save(img)
        # A clipped render snaps to whole pixels, so the origin is the pixel
        # corner, not the requested coordinate. irect gives it exactly.
        origin_x = pix.irect[0] / scale
        origin_y = pix.irect[1] / scale

        env = dict(os.environ, OMP_THREAD_LIMIT="1")
        proc = subprocess.run(
            [exe, str(img), "stdout", "--dpi", str(dpi), "tsv"],
            capture_output=True, text=True, env=env,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"tesseract failed on page {page.number + 1}: "
                               f"{proc.stderr.strip()[:200]}")

    words = []
    for line in proc.stdout.splitlines()[1:]:
        cols = line.split("\t")
        if len(cols) < 12 or cols[0] != "5":
            continue
        text = "\t".join(cols[11:]).strip()
        if not text:
            continue
        try:
            left, top, width, height = (float(cols[6]), float(cols[7]),
                                        float(cols[8]), float(cols[9]))
            conf = float(cols[10])
        except ValueError:
            continue
        # tesseract's line_num restarts per paragraph, so pack block+paragraph
        # into the block slot: (block, line) must be unique or cells from
        # different paragraphs get merged into one giant line.
        block_key = int(cols[2]) * 1000 + int(cols[3])   # block_num, par_num
        words.append((
            origin_x + left / scale,
            origin_y + top / scale,
            origin_x + (left + width) / scale,
            origin_y + (top + height) / scale,
            text,
            block_key,
            int(cols[4]),   # line_num
            int(cols[5]),   # word_num
            conf,
        ))
    words.sort(key=lambda w: (round(w[1], 1), w[0]))
    return words


def ocr_region_words(page, rect, dpi: int = DEFAULT_DPI, lang: str = DEFAULT_LANG,
                     block_namespace: int = 0):
    """OCR just `rect` of a page (an embedded image) and return page-space words."""
    words = ocr_page_words(page, dpi=dpi, lang=lang, clip=rect)
    if block_namespace:
        words = [(w[0], w[1], w[2], w[3], w[4], w[5] + block_namespace * 1_000_000,
                  w[6], w[7], w[8]) for w in words]
    return words


def word_conf(word) -> float:
    """Confidence for an OCR word tuple; native PyMuPDF words are trusted (100)."""
    return word[8] if len(word) > 8 else 100.0
