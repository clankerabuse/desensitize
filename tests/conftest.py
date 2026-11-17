"""Test fixtures: a synthetic 'credit report' full of fake PII.

Nothing here is real data. The fixture deliberately reproduces the awkward
layouts that broke earlier versions:

* a left-margin section header ("Employers") with its value on the next line
* a multi-column name row (four variants on one line)
* a table row whose value sits in a second column far to the right
* a street address split across cells, leaving a bare house number + street name
* masked SSNs, bare 9-digit SSNs, "#1234" identifier tails
"""
from __future__ import annotations

import pymupdf
import pytest

from .fake_data import FAKE


def _page1(doc):
    page = doc.new_page()
    y = 60
    for text in [
        "CREDIT REPORT - TEST FIXTURE",
        f"Consumer Name: {FAKE['name']}",
        f"Also Known As: {FAKE['aka']}",
        f"Social Security Number: {FAKE['ssn']}",
        f"Date of Birth: {FAKE['dob']}",
        f"Address: {FAKE['street']}, {FAKE['city_line']}",
        f"E-mail: {FAKE['email']}",
        f"Phone: {FAKE['phone']}",
        f"Employer: {FAKE['employer']}",
        f"Account Number: {FAKE['account']}",
        f"Reference Id {FAKE['masked_id']}",
        f"Prior SSN on file: {FAKE['ssn_masked']}",
        f"Alt SSN {FAKE['ssn_bare']} reported by furnisher",
    ]:
        page.insert_text((40, y), text, fontsize=10)
        y += 18
    return page


def _page2(doc):
    """Section headers with values underneath, plus a two-column table row."""
    page = doc.new_page()
    page.insert_text((70, 43), "Names", fontsize=10)
    page.insert_text((70, 204), "Addresses", fontsize=10)
    page.insert_text((70, 326), "Employers", fontsize=10)
    page.insert_text((70, 43 + 500), "Accounts", fontsize=10)

    # four name variants on the same line
    for i, variant in enumerate([FAKE["name"], FAKE["aka"], FAKE["name"], FAKE["aka"]]):
        page.insert_text((83 + i * 123, 95), variant, fontsize=9)

    # address block: street split from suffix, then city/state/ZIP line
    page.insert_text((83, 255), "1387 CENTRAL", fontsize=9)
    page.insert_text((206, 255), "AVE", fontsize=9)
    page.insert_text((83, 268), FAKE["city_line"], fontsize=9)

    # employer value sits below its header
    page.insert_text((83, 378), FAKE["employer"], fontsize=9)

    # table row: label left, value in a far column
    page.insert_text((100, 638), "Creditor", fontsize=9)
    page.insert_text((321, 638), FAKE["creditor"], fontsize=9)
    page.insert_text((100, 655), "Account Number", fontsize=9)
    page.insert_text((321, 655), FAKE["account"], fontsize=9)
    page.insert_text((100, 707), "Date Opened", fontsize=9)
    page.insert_text((321, 707), "01/07/2023", fontsize=9)
    return page


@pytest.fixture
def report_pdf(tmp_path):
    """Path to a generated two-page fake report."""
    doc = pymupdf.open()
    _page1(doc)
    _page2(doc)
    path = tmp_path / "creditReport_6320581239.pdf"
    doc.save(path)
    doc.close()
    return path


@pytest.fixture
def scan_pdf(tmp_path, report_pdf):
    """Image-only copy of the fake report: no text layer, like a real scan."""
    src = pymupdf.open(report_pdf)
    out = pymupdf.open()
    for page in src:
        pix = page.get_pixmap(dpi=200)
        new = out.new_page(width=page.rect.width, height=page.rect.height)
        new.insert_image(new.rect, stream=pix.tobytes("jpeg", jpg_quality=85))
    path = tmp_path / "scanned_creditReport.pdf"
    out.save(path)
    out.close()
    src.close()
    return path


@pytest.fixture
def mixed_pdf(tmp_path, report_pdf):
    """Page 1 textual, page 2 image-only."""
    src = pymupdf.open(report_pdf)
    out = pymupdf.open()
    out.insert_pdf(src, from_page=0, to_page=0)
    pix = src[1].get_pixmap(dpi=200)
    new = out.new_page(width=src[1].rect.width, height=src[1].rect.height)
    new.insert_image(new.rect, stream=pix.tobytes("jpeg", jpg_quality=85))
    path = tmp_path / "mixed.pdf"
    out.save(path)
    out.close()
    src.close()
    return path


@pytest.fixture
def blank_pdf(tmp_path):
    """A page with no text layer at all (stands in for a scan)."""
    doc = pymupdf.open()
    doc.new_page()
    path = tmp_path / "scan.pdf"
    doc.save(path)
    doc.close()
    return path


@pytest.fixture
def out_dir(tmp_path):
    return tmp_path / "agent-friendly"
