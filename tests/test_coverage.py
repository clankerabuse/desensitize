"""Coverage: one policy (everything readable + proof), and what can still be tuned.

There used to be a fast/default/full/paranoid ladder. It is gone: a level that
skipped a pasted ID card because it covered 0.19% of the page was a level whose
owner could not see the leak.
"""
from __future__ import annotations

import json
import shutil

import pymupdf
import pytest

from pdf_redact import POLICY, Redactor, resolve_policy
from pdf_redact.cli import main

requires_tesseract = pytest.mark.skipif(
    shutil.which("tesseract") is None, reason="tesseract not installed")


def dark_fraction(path, rect, dpi: int = 200) -> float:
    with pymupdf.open(path) as doc:
        pix = doc[0].get_pixmap(dpi=dpi, clip=rect, alpha=False)
    data = pix.samples
    return sum(1 for b in data if b < 160) / max(1, len(data))


def test_the_policy_is_the_strict_one():
    assert POLICY["ocr_images"] is True            # no picture is below notice
    assert POLICY["min_conf"] == 80.0              # shaky words fail closed
    assert POLICY["image_min_pt"] == (8.0, 4.0)    # down to an icon
    assert POLICY["image_min_src_px"] == 64
    assert POLICY["image_min_area_frac"] == 0.0
    assert POLICY["verify_deep"] is True           # the pixels are re-OCRd


def test_overrides_beat_the_policy():
    cfg = resolve_policy(min_conf=95, ocr_images=False)
    assert cfg["min_conf"] == 95 and cfg["ocr_images"] is False
    assert cfg["verify_deep"] is True              # untouched settings stay strict


def test_unknown_setting_is_rejected():
    with pytest.raises(ValueError):
        resolve_policy(level="fast")


def test_engine_applies_the_policy(tmp_path):
    r = Redactor(out_dir=tmp_path)
    assert r.verify_deep is True and r.min_conf == 80.0 and r.ocr_images is True
    assert Redactor(out_dir=tmp_path, min_conf=50).min_conf == 50.0
    assert Redactor(out_dir=tmp_path, ocr_images=False).ocr_images is False


@requires_tesseract
def test_icon_sized_picture_is_examined(tmp_path, out_dir):
    """A 40x14 pt crop is 0.11% of a letter page and used to be skipped."""
    shot = pymupdf.open()
    sp = shot.new_page(width=40, height=14)
    sp.insert_text((1, 10), "SSN 512-84-9931", fontsize=6)
    png = sp.get_pixmap(dpi=300).tobytes("png")
    shot.close()

    doc = pymupdf.open()
    pg = doc.new_page(width=612, height=792)
    pg.insert_text((60, 60), "Statement of account for the billing period", fontsize=11)
    pg.insert_text((60, 76), "Balance due 1200.00 minimum payment 25.00", fontsize=11)
    rect = pymupdf.Rect(60, 90, 100, 104)
    pg.insert_image(rect, stream=png)
    path = tmp_path / "icon.pdf"
    doc.save(path)
    doc.close()

    result = Redactor(out_dir=out_dir).redact([path])
    assert result.documents[0].image_regions == 1
    assert dark_fraction(result.documents[0].output, rect) < dark_fraction(path, rect) * 0.8


def test_every_copy_gets_a_verification(report_pdf, out_dir):
    result = Redactor(out_dir=out_dir).redact([report_pdf])
    assert set(result.verifications) == {report_pdf.name}
    assert result.verify_deep is True
    assert result.clean is True


@requires_tesseract
def test_a_pixel_leak_found_by_the_proof_stops_the_run(image_pdf, out_dir, monkeypatch):
    """The point of the deep check is that it can fail the run."""
    from pdf_redact.verify import VerificationReport

    path, _rect = image_pdf
    fake = VerificationReport()
    fake.leak_total = 3
    fake.leaks_by_category["SSN"] = 3
    monkeypatch.setattr("pdf_redact.engine.ocr_rescan", lambda *a, **k: fake)

    result = Redactor(out_dir=out_dir).redact([path])
    assert result.clean is False

    out_dir2 = out_dir.parent / "second"
    assert main([str(path), "-o", str(out_dir2), "-q"]) == 2


def test_a_text_only_document_pays_nothing_for_the_proof(report_pdf, out_dir, monkeypatch):
    """No OCR'd pixels means there is nothing to re-OCR."""
    def boom(*_a, **_k):
        raise AssertionError("the pixel proof should not run on a text-only document")

    monkeypatch.setattr("pdf_redact.engine.ocr_rescan", boom)
    result = Redactor(out_dir=out_dir).redact([report_pdf])
    assert result.clean is True


def test_the_old_level_flag_is_gone(report_pdf, out_dir):
    with pytest.raises(SystemExit):
        main([str(report_pdf), "-o", str(out_dir), "--level", "fast", "-q"])


def test_manifest_records_the_proof(report_pdf, out_dir, tmp_path):
    manifest = tmp_path / "m.json"
    assert main([str(report_pdf), "-o", str(out_dir),
                 "--report", str(manifest), "-q"]) == 0
    data = json.loads(manifest.read_text())
    assert data["verify_deep"] is True
    assert "level" not in data
    assert data["coverage"]


def test_no_ocr_images_is_still_available(report_pdf, out_dir):
    result = Redactor(out_dir=out_dir, ocr_images=False).redact([report_pdf])
    assert result.documents[0].image_regions == 0
