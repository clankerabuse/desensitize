"""Regressions found by `eval/` -- each of these leaked a planted value before.

The eval harness generates synthetic statements with known PII (text, pictures
and scans), redacts them, then re-derives leaks from the copies independently.
Every test here is a case that came out of it.
"""
from __future__ import annotations

from collections import Counter

import pymupdf

from pdf_redact import redact
from pdf_redact.detect import detect_in_cell, label_only
from pdf_redact.layout import cells_from_words


def _text(path) -> str:
    with pymupdf.open(path) as doc:
        return "\n".join(p.get_text("text") for p in doc)


def test_short_cell_is_not_mistaken_for_a_label():
    # The label tables are embedded in "^\s*{pat}\s*:?$"; without a group the
    # anchors bound to the first/last alternative only, so any cell containing
    # "reference" counted as a name label.
    assert label_only("Reference Id #2756") is None
    assert label_only("Id #2756") is None
    assert label_only("Patient") == "NAME"
    # a creditor list must not be treated as a person-name field
    assert label_only("Creditor Names:") is None


def test_dob_cue_only_takes_the_date_beside_it():
    text = ("services rendered on 09/18/2023. Our records show date of birth "
            "05/18/1973 and a social security number on file")
    got = [(text[s:e], lab) for s, e, lab in detect_in_cell(text, set(), Counter())]
    assert ("05/18/1973", "DOB") in got
    assert not any(tok == "09/18/2023" for tok, _lab in got), \
        "a service date is not a date of birth"


def test_all_caps_transaction_lines_survive():
    freq = Counter({"pos purchase": 4, "online transfer": 3, "wire in": 5})
    for text in ("POS PURCHASE NORTHSIDE MARKET", "ONLINE TRANSFER TO SAVINGS",
                 "WIRE IN", "RECURRING PAYMENT UTILITIES"):
        assert detect_in_cell(text, set(), freq) == [], text


def test_truncated_email_is_still_caught():
    # a screenshot edge cuts the domain: the local part is the PII
    text = "Email devereaux.kowalski@corp.e Card Number: 4955"
    got = [text[s:e] for s, e, _l in detect_in_cell(text, set(), Counter())]
    assert "devereaux.kowalski@corp.e" in got


def test_salutation_and_signature_names_are_caught():
    for text in ("Dear Delphine Petrakis,", "Sincerely, Delphine Petrakis",
                 "Records were requested by Maribel Nakamura of the practice"):
        got = [text[s:e] for s, e, lab in detect_in_cell(text, set(), Counter())
               if lab == "NAME"]
        assert any("Petrakis" in g or "Nakamura" in g for g in got), text


def test_name_under_a_salutation_on_its_own_line(tmp_path):
    """Letters sign like this: "Sincerely," on one line, the name 20pt below on
    the next -- two separate text blocks, so nothing carries the cue down."""
    doc = pymupdf.open()
    pg = doc.new_page(width=612, height=792)
    pg.insert_text((54, 100), "We have completed our review of your claim.",
                   fontsize=10)
    pg.insert_text((54, 160), "Sincerely,", fontsize=10)
    pg.insert_text((54, 180), "Terrence Halloran", fontsize=10)
    pg.insert_text((54, 194), "Claims Specialist", fontsize=9)
    src = tmp_path / "letter.pdf"
    doc.save(src)
    doc.close()

    result = redact([src], out_dir=tmp_path / "out")
    text = _text(result.documents[0].output)
    assert "Halloran" not in text and "Terrence" not in text


def test_reference_column_header_does_not_open_a_value_block(tmp_path):
    """"REFERENCE" heads a column, it is not a person label: reading it as one
    swallowed the whole table below, amounts and all."""
    doc = pymupdf.open()
    pg = doc.new_page(width=612, height=792)
    cols = [56, 176, 276, 376]
    for x, text in zip(cols, ("REFERENCE", "TYPE", "DATE", "AMOUNT")):
        pg.insert_text((x, 231), text, fontsize=8.5)
    rows = [("2810144999", "WIRE IN", "2023-03-21", "$1886.00"),
            ("9756134681", "WIRE IN", "2023-03-24", "$4006.00")]
    for i, row in enumerate(rows):
        for x, text in zip(cols, row):
            pg.insert_text((x, 244 + i * 13), text, fontsize=8.5)
    src = tmp_path / "wire.pdf"
    doc.save(src)
    doc.close()

    result = redact([src], out_dir=tmp_path / "out")
    text = _text(result.documents[0].output)
    assert "2810144999" not in text and "9756134681" not in text
    assert "$1886.00" in text and "$4006.00" in text


def test_ocr_line_halves_become_one_cell():
    # tesseract splits one visual line into two blocks with 0.2 pt of jitter;
    # grouped on (block, line) the DOB date was torn in half and half survived
    words = [
        (336.5, 235.0, 379.9, 243.8, "September", 1, 1, 0, 92.0),
        (383.5, 235.2, 394.3, 243.1, "13,", 2, 1, 0, 96.0),
        (398.4, 235.2, 417.4, 241.9, "1965", 2, 1, 1, 96.0),
    ]
    cells = cells_from_words(words)
    assert len(cells) == 1
    assert cells[0]["text"] == "September 13, 1965"


def _picture_leaf(path, ssn: str) -> None:
    shot = pymupdf.open()
    sp = shot.new_page(width=200, height=60)
    sp.insert_text((6, 20), f"SSN {ssn}", fontsize=10)
    png = sp.get_pixmap(dpi=200).tobytes("png")
    shot.close()

    doc = pymupdf.open()
    pg = doc.new_page(width=400, height=300)
    pg.insert_text((40, 40), "Statement of account for the billing period",
                   fontsize=10)
    pg.insert_image(pymupdf.Rect(40, 80, 300, 160), stream=png)
    doc.save(path)
    doc.close()


def test_a_batch_does_not_share_image_ocr_between_documents(tmp_path):
    """xrefs restart in every file: a cache keyed on them hands file A's words
    to file B's picture, which leaves B's values unredacted."""
    a, b = tmp_path / "a.pdf", tmp_path / "b.pdf"
    _picture_leaf(a, "512-84-9931")
    _picture_leaf(b, "637-19-2288")

    result = redact([a, b], out_dir=tmp_path / "out")
    for doc in result.documents:
        text = _text(doc.output)
        assert "512-84-9931" not in text and "512849931" not in text, doc.source.name
        assert "637-19-2288" not in text and "637192288" not in text, doc.source.name


def test_wrapped_prose_keeps_its_cue(tmp_path):
    """The DOB cue can end a line with the date on the next one."""
    doc = pymupdf.open()
    pg = doc.new_page(width=612, height=792)
    pg.insert_textbox(pymupdf.Rect(54, 54, 250, 300),
                      "Patient record. Our records show date of birth 05/18/1973 "
                      "and a social security number 512-84-9931 on file.",
                      fontsize=10)
    src = tmp_path / "wrap.pdf"
    doc.save(src)
    doc.close()

    result = redact([src], out_dir=tmp_path / "out")
    text = _text(result.documents[0].output)
    assert "05/18/1973" not in text
    assert "1973" not in text
