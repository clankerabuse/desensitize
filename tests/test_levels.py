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
    # paranoid is full coverage plus proof
    assert set(LEVELS) == {"fast", "default", "full", "paranoid"}
    assert LEVELS["paranoid"]["verify_deep"] is True
    assert all(resolve_level(name)["verify_deep"] is False
               for name in ("fast", "default", "full"))


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


def test_engine_verifies_every_copy(report_pdf, out_dir):
    result = Redactor(out_dir=out_dir, level="default").redact([report_pdf])
    assert set(result.verifications) == {report_pdf.name}
    assert result.clean is True


@requires_tesseract
def test_paranoid_fails_the_run_when_a_pixel_leak_is_found(image_pdf, out_dir, monkeypatch):
    """The level is only meaningful if a bad deep check actually stops the run."""
    from pdf_redact.verify import VerificationReport

    path, _rect = image_pdf
    fake = VerificationReport()
    fake.leak_total = 3
    fake.leaks_by_category["SSN"] = 3
    monkeypatch.setattr("pdf_redact.engine.ocr_rescan", lambda *a, **k: fake)

    result = Redactor(out_dir=out_dir, level="paranoid").redact([path])
    assert result.clean is False

    out_dir2 = out_dir.parent / "second"
    assert main([str(path), "-o", str(out_dir2), "--level", "paranoid", "-q"]) == 2


def test_paranoid_skips_the_pixel_rescan_when_nothing_was_ocrd(report_pdf, out_dir, monkeypatch):
    """A text-only document has no pixels to prove: no OCR pass, no cost."""
    def boom(*_a, **_k):
        raise AssertionError("deep rescan should not run on a text-only document")

    monkeypatch.setattr("pdf_redact.engine.ocr_rescan", boom)
    result = Redactor(out_dir=out_dir, level="paranoid").redact([report_pdf])
    assert result.clean is True


def test_verify_deep_can_be_switched_off_at_paranoid(report_pdf, out_dir):
    r = Redactor(out_dir=out_dir, level="paranoid", verify_deep=False)
    assert r.verify_deep is False


def test_cli_records_the_level(report_pdf, out_dir, tmp_path):
    manifest = tmp_path / "m.json"
    assert main([str(report_pdf), "-o", str(out_dir), "--level", "fast",
                 "--report", str(manifest), "-q"]) == 0
    data = json.loads(manifest.read_text())
    assert data["level"] == "fast"
    assert data["verify_deep"] is False

    paranoid = tmp_path / "p.json"
    assert main([str(report_pdf), "-o", str(tmp_path / "p2"), "--level", "paranoid",
                 "--report", str(paranoid), "-q"]) == 0
    assert json.loads(paranoid.read_text())["verify_deep"] is True
