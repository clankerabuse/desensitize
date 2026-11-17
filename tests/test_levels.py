"""Levels: fast / default / full, and the overrides that beat them."""
from __future__ import annotations

import json
import shutil

import pymupdf
import pytest

from pdf_redact import LEVELS, Redactor, resolve_level
from pdf_redact.cli import main

from .fake_data import FAKE

requires_tesseract = pytest.mark.skipif(
    shutil.which("tesseract") is None, reason="tesseract not installed")

def dark_fraction(path, rect, dpi: int = 200) -> float:
    with pymupdf.open(path) as doc:
        pix = doc[0].get_pixmap(dpi=dpi, clip=rect, alpha=False)
    data = pix.samples
    return sum(1 for b in data if b < 160) / max(1, len(data))


def test_level_table_escalates():
    assert LEVELS["fast"]["ocr_images"] is False
    assert LEVELS["default"]["ocr_images"] is True
    assert LEVELS["full"]["min_conf"] > LEVELS["default"]["min_conf"]
    assert LEVELS["full"]["image_min_area_frac"] < LEVELS["default"]["image_min_area_frac"]
    assert LEVELS["full"]["image_min_src_px"] < LEVELS["default"]["image_min_src_px"]


def test_overrides_beat_the_level():
    cfg = resolve_level("fast", ocr_images=True, min_conf=95)
    assert cfg["ocr_images"] is True and cfg["min_conf"] == 95
    assert cfg["level"] == "fast"


def test_unknown_level_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        Redactor(out_dir=tmp_path, level="maximum")


def test_engine_applies_level_settings(tmp_path):
    assert Redactor(out_dir=tmp_path, level="fast").ocr_images is False
    full = Redactor(out_dir=tmp_path, level="full")
    assert full.min_conf == 80.0 and full.image_min_area_frac == 0.0
    bumped = Redactor(out_dir=tmp_path, level="full", min_conf=50)
    assert bumped.min_conf == 50.0


def test_default_skips_a_60x20_picture(small_image_pdf, out_dir):
    """Default treats a 60x20 pt picture as an icon: it is not examined."""
    path, rect = small_image_pdf
    result = Redactor(out_dir=out_dir, level="default").redact([path])
    assert result.documents[0].image_regions == 0
    assert dark_fraction(result.documents[0].output, rect) > 0.05


@requires_tesseract
def test_full_finds_the_same_picture(small_image_pdf, out_dir):
    """Full drops the area floor, so the SSN in that picture gets burned."""
    path, rect = small_image_pdf
    result = Redactor(out_dir=out_dir, level="full").redact([path])
    doc = result.documents[0]
    assert doc.image_regions == 1
    assert dark_fraction(path, rect) > 0.05
    assert dark_fraction(doc.output, rect) < dark_fraction(path, rect) * 0.6

    with pymupdf.open(doc.output) as out:
        text = "\n".join(p.get_text("text") for p in out)
    assert FAKE["ssn"] not in text


@requires_tesseract
def test_fast_ignores_even_large_pictures(image_pdf, out_dir):
    path, rect = image_pdf
    result = Redactor(out_dir=out_dir, level="fast").redact([path])
    doc = result.documents[0]
    assert doc.image_regions == 0
    assert dark_fraction(doc.output, rect) > dark_fraction(path, rect) * 0.9


def test_cli_records_the_level(report_pdf, out_dir, tmp_path):
    manifest = tmp_path / "m.json"
    assert main([str(report_pdf), "-o", str(out_dir), "--level", "fast",
                 "--report", str(manifest), "-q"]) == 0
    assert json.loads(manifest.read_text())["level"] == "fast"
