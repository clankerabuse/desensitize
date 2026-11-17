"""Unit tests for the value regexes and the label tables."""
from pdf_redact.patterns import (
    ADDRESS_RE,
    EMAIL_RE,
    MASK_TAIL_RE,
    NUMBER_RE,
    PHONE_RE,
    SSN_RE,
    ZIP_RE,
    norm,
)


def test_ssn_variants():
    for text in ("512-84-9931", "512 84 9931", "512849931", "XXX-XX-9931"):
        assert SSN_RE.search(text), text


def test_ssn_does_not_eat_longer_numbers():
    assert not SSN_RE.search("441700928377162")
    assert not SSN_RE.search("2026")


def test_email():
    assert EMAIL_RE.search("write to zelda.wexington@example.org now")
    assert not EMAIL_RE.search("not an email at all")


def test_phone():
    assert PHONE_RE.search("call (217) 555-0182")
    assert PHONE_RE.search("call 217-555-0182")
    assert not PHONE_RE.search("account 441700928377162")


def test_zip_not_inside_longer_number():
    assert ZIP_RE.search("BOULDER CO 80302")
    assert ZIP_RE.search("80302-1234")
    assert not ZIP_RE.search("441700928377162")


def test_address_forms():
    assert ADDRESS_RE.search("4417 Marigold Terrace Apt 3B")
    assert ADDRESS_RE.search("PO Box 4417")
    assert not ADDRESS_RE.search("Single family dwelling")


def test_long_identifier_and_masked_tail():
    assert NUMBER_RE.search("441700928377162")
    assert NUMBER_RE.search("AB7712XQ0093")
    assert MASK_TAIL_RE.search("#2756")
    assert MASK_TAIL_RE.search("XXXXXX8393")


def test_norm_strips_edge_punctuation():
    assert norm("Account:") == norm("account")
    assert norm("  [NAME]  ") == "name"
