"""End-to-end: generate a fake report, redact it, then verify the copy."""
from __future__ import annotations

import hashlib
import json

import pymupdf
import pytest

from desensitize import redact, scan_copy
from desensitize.cli import main
from desensitize.engine import NoTextLayerError, Redactor, safe_output_name

from .fake_data import FAKE

PII_TOKENS = [
    FAKE["ssn"], FAKE["ssn_bare"], FAKE["ssn_masked"], FAKE["email"], FAKE["phone"],
    "1387", "CENTRAL", "BOWLING", "GREEN", "42101", "Wexington", "WEXINGTON",
    "KAYNE", "PETROGLYPH", "441700928377162", "#2756", "1971",
]


def copy_text(path) -> str:
    with pymupdf.open(path) as doc:
        return "\n".join(p.get_text("text") for p in doc)


def digest(path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_copies_are_written_and_original_untouched(report_pdf, out_dir):
    before = digest(report_pdf)
    result = redact([report_pdf], out_dir=out_dir)

    assert result.documents[0].output.exists()
    assert digest(report_pdf) == before, "the input must never be modified"
    assert result.total > 0
    assert result.documents[0].pages == 2


def test_no_sensitive_value_survives(report_pdf, out_dir):
    result = redact([report_pdf], out_dir=out_dir)
    text = copy_text(result.documents[0].output)

    for token in PII_TOKENS:
        assert token not in text, f"leaked: {token}"
    assert "@" not in text


def test_placeholders_are_typed(report_pdf, out_dir):
    result = redact([report_pdf], out_dir=out_dir)
    text = copy_text(result.documents[0].output)

    for label in ("[NAME]", "[SSN]", "[ADDRESS]", "[EMPLOYER]", "[NUMBER]"):
        assert label in text, f"missing placeholder {label}"


def test_creditor_data_stays_readable(report_pdf, out_dir):
    result = redact([report_pdf], out_dir=out_dir)
    text = copy_text(result.documents[0].output)

    assert FAKE["creditor"] in text      # creditor names are analysis material
    assert "01/07/2023" in text          # dates opened must survive


def test_self_check_reports_clean(report_pdf, out_dir):
    result = redact([report_pdf], out_dir=out_dir)
    report = scan_copy(result.documents[0].output,
                       result.redacted_hashes, result.unredacted_vocab)
    assert report.clean, report.as_dict()


def test_dry_run_writes_nothing(report_pdf, out_dir):
    result = Redactor(out_dir=out_dir).redact([report_pdf], dry_run=True)
    assert result.total > 0          # it still plans every mark
    assert not out_dir.exists()      # ...but writes no copy


def test_scanned_pdf_is_refused_when_ocr_disabled(blank_pdf, out_dir):
    with pytest.raises(NoTextLayerError):
        redact([blank_pdf], out_dir=out_dir, ocr="off")


def test_cli_exit_codes(report_pdf, blank_pdf, out_dir, tmp_path, capsys):
    manifest = tmp_path / "manifest.json"
    assert main([str(report_pdf), "-o", str(out_dir), "--report", str(manifest)]) == 0
    data = json.loads(manifest.read_text())
    assert data["clean"] is True
    assert data["redactions_total"] > 0
    assert all(v == 0 for v in data["verification"][report_pdf.name]
               ["residual_pattern_hits"].values())

    assert main([str(tmp_path / "nope.pdf")]) == 1
    assert main([str(blank_pdf), "--ocr", "off"]) == 3   # scan refused, not faked


def test_cli_dry_run_writes_nothing(report_pdf, out_dir):
    assert main([str(report_pdf), "-o", str(out_dir), "--dry-run", "-q"]) == 0
    assert not out_dir.exists()


def test_output_filename_drops_identifiers():
    from pathlib import Path
    assert safe_output_name(Path("creditReport_6320581239.pdf")) == "creditReport_redacted.pdf"
    assert safe_output_name(Path("Annual Credit Report - Experian.pdf")) == \
        "Annual Credit Report - Experian.pdf"
