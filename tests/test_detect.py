"""Unit tests for span detection inside a cell."""
from collections import Counter

from pdf_redact.detect import detect_in_cell, label_only, name_spans
from pdf_redact.patterns import h


def labels(text, names=None, freq=None):
    spans = detect_in_cell(text, names or set(), freq or Counter())
    return [(text[s:e], lab) for s, e, lab in spans]


def test_label_only_matching():
    assert label_only("Account Number") == "ACCT"
    assert label_only("Employers") == "EMPLOYER"
    assert label_only("Former Name(s):") == "NAME"
    assert label_only("Dear Zelda") is None


def test_label_prefix_takes_the_value():
    got = labels("Social Security Number: 512-84-9931")
    assert ("512-84-9931", "SSN") in got


def test_creditor_name_label_is_not_a_person_name():
    got = labels("Creditor Names: Capital One, Discover")
    assert not any(lab == "NAME" for _tok, lab in got)


def test_bare_values_without_labels():
    got = labels("441700928377162")
    assert got and got[0][1] == "NUMBER"
    got = labels("zelda.wexington@example.org")
    assert ("zelda.wexington@example.org", "EMAIL") in got


def test_dob_context_takes_the_year_only():
    got = labels("Year of Birth 1971")
    assert ("1971", "DOB") in got
    # a bare year elsewhere is left alone
    assert not any(lab == "DOB" for _tok, lab in labels("Status Updated Feb 2024"))


def test_address_fragment_needs_a_street_word():
    assert labels("1387 CENTRAL")[0][1] == "ADDRESS"
    assert labels("6 Accounts") == []


def test_name_spans_need_repetition_or_learning():
    text = "Zelda Q Wexington"
    # once only: too risky, left alone
    assert name_spans(text, set(), Counter()) == []
    # learned from a labelled field: redacted
    assert name_spans(text, {"zelda"}, Counter())
    # or seen twice across the inputs
    assert name_spans(text, set(), Counter({"zelda q": 2}))


def test_company_names_survive():
    assert name_spans("Capital One Bank", set(), Counter({"capital one": 9})) == []


def test_learned_name_catches_bare_mention():
    got = labels("Authorized user: Wexington, Z.", names={"wexington"})
    assert any(lab == "NAME" and tok.startswith("Wexington") for tok, lab in got)


def test_hash_is_value_free():
    # the tool stores digests, never the value itself
    digest = h("512-84-9931")
    assert len(digest) == 16 and "512" not in digest
