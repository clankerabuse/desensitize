"""Regressions found by `eval/` -- each of these leaked a planted value before.

The eval harness generates synthetic statements with known PII (text, pictures
and scans), redacts them, then re-derives leaks from the copies independently.
Every test here is a case that came out of it.
"""
from __future__ import annotations

import shutil
import subprocess
from collections import Counter

import pymupdf
import pytest

from desensitize import redact
from desensitize.detect import detect_in_cell, label_only
from desensitize.engine import Redactor
from desensitize.layout import cells_from_words

requires_tesseract = pytest.mark.skipif(
    shutil.which("tesseract") is None,
    reason="tesseract not installed; OCR paths cannot be exercised",
)

requires_pdftotext = pytest.mark.skipif(
    shutil.which("pdftotext") is None,
    reason="poppler not installed; cannot check the copy against pdftotext",
)


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


def _objects_of(path):
    """Every string a redactor forgets: annots, fields, bookmarks, attachments."""
    with pymupdf.open(path) as doc:
        annots, widgets = [], []
        for page in doc:
            for a in page.annots() or []:
                annots.append((a.info or {}).get("content") or "")
            for w in page.widgets() or []:
                widgets.append(w.field_value or "")
        return {"annots": annots, "widgets": widgets, "toc": doc.get_toc(),
                "attachments": doc.embfile_names() or []}


def test_form_field_values_are_redacted(tmp_path):
    doc = pymupdf.open()
    pg = doc.new_page(width=612, height=792)
    pg.insert_text((60, 60), "Enrolment form", fontsize=12)
    for i, (name, value) in enumerate((("ssn", "512-84-9931"),
                                       ("holder", "Zelda Q Wexington"))):
        w = pymupdf.Widget()
        w.field_name = name
        w.field_type = pymupdf.PDF_WIDGET_TYPE_TEXT
        w.rect = pymupdf.Rect(60, 90 + i * 30, 260, 112 + i * 30)
        w.field_value = value
        pg.add_widget(w)
    src = tmp_path / "form.pdf"
    doc.save(src)
    doc.close()

    result = redact([src], out_dir=tmp_path / "out")
    got = _objects_of(result.documents[0].output)
    assert not any("512" in v or "Wexington" in v for v in got["widgets"]), got["widgets"]


def test_annotation_text_is_redacted(tmp_path):
    doc = pymupdf.open()
    pg = doc.new_page(width=612, height=792)
    pg.insert_text((60, 60), "Dispute form", fontsize=12)
    pg.add_freetext_annot(pymupdf.Rect(60, 100, 400, 140),
                          "Please verify SSN 512-84-9931 before processing",
                          fontsize=9)
    src = tmp_path / "annot.pdf"
    doc.save(src)
    doc.close()

    result = redact([src], out_dir=tmp_path / "out")
    got = _objects_of(result.documents[0].output)
    # apply_redactions may drop an annotation that sat under a redaction mark;
    # what must not happen is the note surviving with the value still in it
    assert not any("512-84-9931" in a for a in got["annots"]), got["annots"]


def test_bookmark_titles_are_replaced_whole(tmp_path):
    doc = pymupdf.open()
    pg = doc.new_page(width=612, height=792)
    pg.insert_text((60, 60), "Account packet", fontsize=12)
    doc.set_toc([[1, "Gideon Q. Moreau - SSN 512-84-9931", 1],
                 [1, "Account summary", 1]])
    src = tmp_path / "bookmarks.pdf"
    doc.save(src)
    doc.close()

    result = redact([src], out_dir=tmp_path / "out")
    toc = _objects_of(result.documents[0].output)["toc"]
    titles = [t for _lvl, t, _p in toc]
    assert not any("Moreau" in t or "512" in t for t in titles), titles
    assert "Account summary" in titles


def test_attachments_are_dropped(tmp_path):
    doc = pymupdf.open()
    pg = doc.new_page(width=612, height=792)
    pg.insert_text((60, 60), "Account packet", fontsize=12)
    doc.embfile_add("notes.txt", b"SSN: 512-84-9931\nName: Zelda Wexington\n")
    src = tmp_path / "attach.pdf"
    doc.save(src)
    doc.close()

    result = redact([src], out_dir=tmp_path / "out")
    assert _objects_of(result.documents[0].output)["attachments"] == []


@requires_pdftotext
def test_text_hidden_by_the_crop_box_is_redacted(tmp_path):
    """A reader never sees the strip; pdftotext reads it."""
    doc = pymupdf.open()
    pg = doc.new_page(width=612, height=792)
    pg.insert_text((60, 60), "Certificate of deposit advice", fontsize=12)
    pg.insert_text((60, 786), "Phone 217-555-0182", fontsize=9)
    pg.set_cropbox(pymupdf.Rect(0, 0, 612, 762))
    src = tmp_path / "crop.pdf"
    doc.save(src)
    doc.close()

    result = redact([src], out_dir=tmp_path / "out")
    out = result.documents[0].output
    with pymupdf.open(out) as d:
        assert d[0].cropbox.height < 780, "the original crop must be restored"
    text = subprocess.run(["pdftotext", "-layout", str(out), "-"],
                          capture_output=True, text=True).stdout
    assert "555-0182" not in text, text


def test_account_holder_prose_names_the_person(tmp_path):
    doc = pymupdf.open()
    pg = doc.new_page(width=612, height=792)
    pg.insert_text((60, 60), "Certificate of deposit advice", fontsize=12)
    pg.insert_text((60, 100), "Account holder Cyrus Oyelaran, certificate 5092717995.",
                   fontsize=9)
    src = tmp_path / "holder.pdf"
    doc.save(src)
    doc.close()

    result = redact([src], out_dir=tmp_path / "out")
    text = _text(result.documents[0].output)
    assert "Oyelaran" not in text and "Cyrus" not in text


# --- image-only documents ---------------------------------------------------

def copy_text(path) -> str:
    with pymupdf.open(path) as doc:
        return "\n".join(p.get_text("text") for p in doc)


def _rotated_scan(tmp_path, rotate: int):
    """A one-page scan whose ink is only upright after `rotate` degrees."""
    src = pymupdf.open()
    page = src.new_page(width=612, height=792)
    page.insert_text((72, 100), "COLDWATER MUTUAL", fontsize=16)
    page.insert_text((72, 150), "Insured: Delphine Rasmussen", fontsize=12)
    page.insert_text((72, 175), "SSN: 616-37-4632", fontsize=12)
    page.insert_text((72, 200), "8758 Maplewood Street, Brookhaven, GA 30319",
                     fontsize=12)
    png = page.get_pixmap(dpi=200).tobytes("jpeg", jpg_quality=80)
    src.close()

    doc = pymupdf.open()
    if rotate in (90, 270):
        new = doc.new_page(width=792, height=612)     # a sheet fed sideways
    else:
        new = doc.new_page(width=612, height=792)
    new.insert_image(new.rect, stream=png, rotate=rotate)
    out = tmp_path / f"rot{rotate}.pdf"
    doc.save(out)
    doc.close()
    return out


@pytest.mark.parametrize("rotate", [90, 180, 270])
@requires_tesseract
def test_sideways_scan_is_un_rotated(tmp_path, out_dir, rotate):
    """A page fed sideways must be read (and redacted) the right way up.

    Tesseract half-reads rotated text, so the old code accepted the garbage
    pass and produced a copy whose columns were in the wrong order.
    """
    src = _rotated_scan(tmp_path, rotate)
    result = Redactor(out_dir=out_dir).redact([src])

    assert result.clean
    text = copy_text(result.documents[0].output)
    assert "616-37-4632" not in text
    assert "Rasmussen" not in text
    assert "Maplewood" not in text
    # the saved copy keeps the rotation the sheet came in with
    with pymupdf.open(result.documents[0].output) as doc:
        assert doc[0].rotation == 0


@requires_tesseract
def test_scan_nothing_could_be_read_is_not_clean(tmp_path, out_dir):
    """A page with ink on it that OCR cannot read is unproven, not clean.

    'No words' used to be indistinguishable from 'nothing sensitive', so an
    unreadable scan was signed off as though it had been checked.
    """
    src = pymupdf.open()
    page = src.new_page(width=612, height=792)
    page.insert_text((72, 100), "SSN 616-37-4632", fontsize=9)
    blur = page.get_pixmap(dpi=55).tobytes("jpeg", jpg_quality=25)
    src.close()
    doc = pymupdf.open()
    new = doc.new_page(width=612, height=792)
    new.insert_image(new.rect, stream=blur)
    scan = tmp_path / "unreadable.pdf"
    doc.save(scan)
    doc.close()

    result = Redactor(out_dir=out_dir).redact([scan])
    assert result.documents[0].unreadable_pages == [0]
    assert not result.clean


@requires_tesseract
def test_blank_scan_is_not_flagged(tmp_path, out_dir):
    """An empty sheet is blank, not unproven: no ink, nothing to read."""
    src = pymupdf.open()
    page = src.new_page(width=612, height=792)
    blank = page.get_pixmap(dpi=150).tobytes("jpeg", jpg_quality=70)
    src.close()
    doc = pymupdf.open()
    new = doc.new_page(width=612, height=792)
    new.insert_image(new.rect, stream=blank)
    scan = tmp_path / "blank.pdf"
    doc.save(scan)
    doc.close()

    result = Redactor(out_dir=out_dir).redact([scan])
    assert result.documents[0].unreadable_pages == []
    assert result.clean


def test_party_of_record_is_a_name_label():
    """'Borrower of record:' names a person, and legal forms phrase it that way."""
    assert label_only("Borrower of record") == "NAME"
    assert label_only("Trustor of record:") == "NAME"
    line = "Borrower of record: Anne-Marie Kowalski"
    spans = detect_in_cell(line, set(), Counter())
    assert any(lab == "NAME" and "Kowalski" in line[a:b] for a, b, lab in spans)
