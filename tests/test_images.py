"""Tests for embedded-image OCR: text hidden in pictures on an otherwise textual page."""
from __future__ import annotations

import shutil

import pymupdf
import pytest

from desensitize import Redactor
from desensitize.layout import image_regions

from .fake_data import FAKE

requires_tesseract = pytest.mark.skipif(
    shutil.which("tesseract") is None,
    reason="tesseract not installed; image OCR cannot be exercised",
)


def copy_text(path) -> str:
    with pymupdf.open(path) as doc:
        return "\n".join(p.get_text("text") for p in doc)


def dark_fraction(page, rect, dpi: int = 200) -> float:
    pix = page.get_pixmap(dpi=dpi, clip=rect, alpha=False)
    data = pix.samples
    return sum(1 for b in data if b < 160) / max(1, len(data))


def test_image_regions_skips_logos_and_tiny_tiles(image_pdf):
    path, rect = image_pdf
    with pymupdf.open(path) as doc:
        regions = image_regions(doc[0])
    assert len(regions) == 1, "the 10x10 logo must not be OCR'd"
    found, _xref = regions[0]
    assert abs(found.width - rect.width) < 2 and abs(found.height - rect.height) < 2


@requires_tesseract
def test_text_inside_an_image_is_detected_and_burned(image_pdf, out_dir):
    path, rect = image_pdf
    result = Redactor(out_dir=out_dir).redact([path])
    doc = result.documents[0]
    assert doc.image_regions >= 1, "the screenshot should have been OCR'd"

    with pymupdf.open(path) as before, pymupdf.open(doc.output) as after:
        ink_before = dark_fraction(before[0], rect)
        ink_after = dark_fraction(after[0], rect)
    assert ink_before > 0.02
    assert ink_after < ink_before * 0.5, "the picture still shows the SSN"

    text = copy_text(doc.output)
    for token in (FAKE["ssn"], FAKE["account"], "42101", "BOWLING"):
        assert token not in text, f"leaked from the image: {token}"
    assert "[SSN]" in text or "[NUMBER]" in text or "[UNCLEAR]" in text


@requires_tesseract
def test_image_ocr_can_be_turned_off(image_pdf, out_dir):
    """With --no-ocr-images the picture is left alone: that is the trade-off."""
    path, rect = image_pdf
    result = Redactor(out_dir=out_dir, ocr_images=False).redact([path])
    doc = result.documents[0]
    assert doc.image_regions == 0

    with pymupdf.open(path) as before, pymupdf.open(doc.output) as after:
        assert dark_fraction(after[0], rect) > dark_fraction(before[0], rect) * 0.9


@requires_tesseract
def test_image_regions_do_not_break_the_text_layer(image_pdf, out_dir):
    path, _rect = image_pdf
    result = Redactor(out_dir=out_dir).redact([path])
    text = copy_text(result.documents[0].output)
    assert "Statement of account" in text      # ordinary text survives
    assert "screenshot below" in text
