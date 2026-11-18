"""Tests for the OCR path: scanned input gets redacted in the pixels, not just the text."""
from __future__ import annotations

import shutil

import pymupdf
import pytest

from desensitize import Redactor, ocr_page_words, ocr_rescan, scan_copy
from desensitize.engine import NoTextLayerError
from desensitize.ocr import OcrUnavailableError

from .conftest import FAKE

requires_tesseract = pytest.mark.skipif(
    shutil.which("tesseract") is None,
    reason="tesseract not installed; OCR paths cannot be exercised",
)

PII_TOKENS = [
    FAKE["ssn"], FAKE["ssn_bare"], FAKE["ssn_masked"], FAKE["email"], FAKE["phone"],
    "1387", "BOWLING", "GREEN", "42101", "Wexington", "PETROGLYPH",
    FAKE["account"], "1971",
]


def copy_text(path) -> str:
    with pymupdf.open(path) as doc:
        return "\n".join(p.get_text("text") for p in doc)


def dark_fraction(page, rect, dpi: int = 200) -> float:
    """Share of pixels in `rect` that are ink (used to prove the ink is gone)."""
    pix = page.get_pixmap(dpi=dpi, clip=rect, alpha=False)
    data = pix.samples
    dark = sum(1 for b in data if b < 160)
    return dark / max(1, len(data))


def find_word_box(path, needle: str, dpi: int = 200):
    with pymupdf.open(path) as doc:
        for page in doc:
            for w in ocr_page_words(page, dpi=dpi):
                if needle in w[4]:
                    return page.number, pymupdf.Rect(w[:4])
    raise AssertionError(f"{needle!r} not found by OCR")


def test_ocr_off_refuses_scans(scan_pdf, out_dir):
    with pytest.raises(NoTextLayerError):
        Redactor(out_dir=out_dir, ocr="off").redact([scan_pdf])


@requires_tesseract
def test_scan_is_redacted_and_pixels_are_burned(scan_pdf, out_dir):
    result = Redactor(out_dir=out_dir, ocr="auto").redact([scan_pdf])
    doc = result.documents[0]
    assert doc.mode == "ocr" and doc.ocr_pages == doc.pages

    # the ink must be gone from the picture, not just from a text layer
    pno, box = find_word_box(scan_pdf, FAKE["ssn"])
    with pymupdf.open(scan_pdf) as before, pymupdf.open(doc.output) as after:
        ink_before = dark_fraction(before[pno], box)
        ink_after = dark_fraction(after[pno], box)
    assert ink_before > 0.15, "fixture should have real ink in that box"
    assert ink_after < ink_before * 0.5, "the SSN pixels were not burned away"

    # every value is gone from the copy, and the rebuild still reads as text
    text = copy_text(doc.output)
    for token in PII_TOKENS:
        assert token not in text, f"leaked: {token}"
    assert "[SSN]" in text or "[NUMBER]" in text
    assert len(text) > 200, "the copy should still be readable"
    # analysis material survives OCR too: creditors and dates stay
    assert "CAPITAL" in text.upper()
    assert "01/07/2023" in text


@requires_tesseract
def test_scan_copy_is_verifiable(scan_pdf, out_dir):
    result = Redactor(out_dir=out_dir, ocr="auto").redact([scan_pdf])
    report = scan_copy(result.documents[0].output,
                       result.redacted_hashes, result.unredacted_vocab)
    assert report.clean, report.as_dict()


@requires_tesseract
def test_deep_rescan_finds_nothing_in_the_pixels(scan_pdf, out_dir):
    result = Redactor(out_dir=out_dir, ocr="auto").redact([scan_pdf])
    deep = ocr_rescan(result.documents[0].output, result.redacted_hashes,
                      result.unredacted_vocab, dpi=200)
    assert deep.leak_total == 0, deep.as_dict()


@requires_tesseract
def test_mixed_document_uses_ocr_only_where_needed(mixed_pdf, out_dir):
    result = Redactor(out_dir=out_dir, ocr="auto").redact([mixed_pdf])
    doc = result.documents[0]
    assert doc.mode == "mixed" and doc.ocr_pages == 1
    text = copy_text(doc.output)
    assert FAKE["ssn"] not in text and FAKE["email"] not in text


@requires_tesseract
def test_low_confidence_words_fail_closed(blank_pdf, out_dir, monkeypatch):
    """OCR noise must be redacted, not guessed at."""
    fake_words = [
        (40, 60, 120, 72, "512-84-9931", 1, 1, 1, 12.0),   # low confidence value
        (40, 90, 120, 102, "Balance", 1, 2, 1, 96.0),       # high confidence label
    ]
    monkeypatch.setattr("desensitize.engine.ocr_page_best",
                        lambda page, dpi=300, lang="eng": (fake_words, page.rotation))
    result = Redactor(out_dir=out_dir, ocr="force").redact([blank_pdf])

    assert result.counts["UNCLEAR"] == 1
    text = copy_text(result.documents[0].output)
    assert "512-84-9931" not in text
    assert "Balance" in text        # confident words are kept (and readable)


def test_missing_tesseract_is_reported(blank_pdf, out_dir, monkeypatch):
    monkeypatch.setattr("desensitize.ocr.shutil.which", lambda name: None)
    monkeypatch.setattr("desensitize.ocr.tesseract_version", lambda: "")
    with pytest.raises(OcrUnavailableError):
        Redactor(out_dir=out_dir, ocr="force").redact([blank_pdf])
