# eval — does the redaction actually remove the data?

A synthetic benchmark for `desens`. It builds documents whose sensitive values
are **known**, runs the tool over them, then looks for those values in the copies
from four independent surfaces. The checker shares no code with the tool: if the
two disagree, the checker is right.

```
python eval/run.py --count 100 --seed 7       # generate, redact, verify
python eval/run.py --regen --count 100        # fresh documents
python eval/run.py --set tricky --regen       # the adversarial corpus
python eval/run.py --dpi 400                  # sharper pixel check, slower
```

`--set` picks the corpus: `normal` (14 everyday archetypes), `tricky` (12
adversarial ones) or `mixed`. There is one coverage policy, so there is no level to
choose.

Everything lands in `eval/data/`: `docs/` (the inputs), `truth.json` (every planted
value, the probes used to look for it, the keep-list, and a sha256 per picture),
`out/` (the copies), `manifest.json` (the tool's own report) and `report.json` (the
independent verdict). `run.py` exits non-zero if any
critical leak survives.

## The documents

Three corpora, plus `mixed` to run all of them together.

**`--set normal`** — fourteen everyday archetypes: credit report (2 pp, account table,
section headers), bank statement (2 pp, ledger, wire instructions), W-2 (boxed form),
insurance letter (prose, salutation, signature block, cc), invoice, medical bill, lease
application (references, employer, signature), utility bill, a pure **scan**
(rasterised pages), a text page with a pasted **screenshot**, a page with a normal
**ID-card crop** and an **icon-sized one**, a **dark-mode** screenshot, a page with
**90°-rotated text and a rotated image**, and a 3-page record with the identity in a
**header and footer**.

**`--set tricky`** — twelve adversarial ones, each a way a redactor gets it wrong:

| archetype | the trap |
|---|---|
| `split_values` | a value wrapped mid-way across two lines, and another split across a page break |
| `fake_redaction` | black boxes, white boxes and strikethroughs painted *over* live glyphs |
| `white_ink` | white-on-white text and a 1.6 pt line at the foot of the page |
| `unicode` | `José Müller-Ångström`, `Calle Ñandú`, embedded TrueType rather than base-14 |
| `annotations` | the SSN in a free-text note, the phone in a sticky note, the name in a form field |
| `bookmarks_attach` | the SSN in a bookmark title, an XMP packet and an attached `.txt` |
| `two_column` | newspaper columns: label in one column, value in the other |
| `rotated_page` | the whole page rotated 180°, plus a 270° block in the margin |
| `noisy_scan` | 200 dpi JPEG, skewed a degree, speckled, grey text |
| `dense_table` | 60 rows at 6 pt — 240 cells of PII under one header row |
| `offscreen` | a phone number below the crop box: invisible, and pdftotext reads it |
| `packed_fields` | `Name: X SSN: Y DOB: Z` and `SSN:Y ACCT:Z` on one line, plus a last-four mention |

**`--set images`** — fourteen documents with **no text layer at all**: the ink is the
document, and everything has to come out of pixels.

| archetype | the trap |
|---|---|
| `photo` | a photographed page: 1.4° off-square, shadow gradient, warm cast, sensor speckle |
| `rot90` / `rot180` / `rot270` | the sheet was fed sideways or upside down — the ink is only upright after a turn |
| `fax` | 120 dpi thin ink, JPEG-40, horizontal streaks |
| `lowcontrast` | beige paper, pale grey ink: a scan of a photocopy of a fax |
| `watermark` | a 54 pt diagonal CONFIDENTIAL laid across the body text |
| `stamp` | a rubber stamp struck across the SSN line, hiding it from OCR |
| `two_column` | a newspaper notice: label in one column, borrower in the other |
| `idcard` | a colour ID card filling the page: photo box, 8 pt type, MRZ-ish strip |
| `mrz` | a passport data page with two machine-readable lines |
| `handwriting` | a signature block written in italic script under printed fields |
| `qr` | a real QR code (segno) holding an SSN — recorded as a known gap, never failed on |
| `email` | a screenshot of an email with the SSN quoted in the body |

Each value is drawn from a seeded RNG — nothing is real — and recorded with the
probes that should find it if it survives:

* `digits` — the number's digits, matched across `-`, `.`, spaces, newlines and
  brackets, and (in pixels) across OCR confusions (`0/O`, `1/I/l`, `5/S`, `8/B`,
  `2/Z`, `6/G`)
* `alnum` — an account/policy/member id, separators optional
* `tokens` — a name or street: every token, in order, within 40 characters
* `text` — an address, a masked SSN, an email

A four-digit-only probe (a masked SSN tail, a birth year) is recorded as **soft**:
it is reported, never failed on, because "2021" is a date as often as it is a leak.

## How a copy is judged

| Surface | What it catches |
|---|---|
| `text` | PyMuPDF extraction of the copy |
| `pdftotext` | a second extractor, in case PyMuPDF is being generous |
| `pixels` | the page rendered at 300 dpi and OCR'd, confusables allowed |
| `imagebox` | each planted picture's box rendered at ≥400 dpi and OCR'd |
| `stream` | every decompressed content stream, searched for the raw value |
| `image-bytes` | a PII picture that survives **byte-identical** is a leak with no OCR needed |
| `annots`, `widgets` | annotation contents and form-field values |
| `outline` | bookmark titles |
| `attachments` | the name and the bytes of every attached file |
| `meta`, `xmp` | DocInfo and the XMP packet |

Before scoring, every probe is looked for in the **input**. A probe the checker
cannot find there (a 6 pt ID in a 58×16 pt crop that tesseract cannot read) is
reported as *unverifiable* and excluded, so a blind spot in the checker can never be
mistaken for a clean document.

## Results

Three runs of 100 documents each, current build:

| corpus | planted values | failing | critical leaks | soft | keep-list | wall clock |
|---|---|---|---|---|---|---|
| `--set normal` | 1 336 | 0 / 100 | **0** | 1 | 704/779 (90%) | 2 m 34 s |
| `--set tricky` | 2 416 | 0 / 100 | **0** | 30 | 234/242 (97%) | 1 m 19 s |
| `--set images` | 496 | 0 / 100 | **0** | 0 | 16/23 (70%) | 15 m 26 s |

Wall clock is redaction plus the full independent verification; the tool alone takes
33 s for 100 documents. The tool's own `--report` self-check agrees (`clean: true`,
exit 0) on both.

* **Soft** findings on the tricky corpus are the deliberate last-four mentions
  (`SSN on file ends in 4632`) — three surfaces × ten documents. They are reported
  and never failed on: four digits are a year as often as they are a tail.
* **Unverifiable** probes (2 tricky, 6 normal, 84 image-only) are values the checker
  cannot find in the *input* either: truncated emails inside pasted screenshots, a name
  and address tesseract cannot read in the speckled scan at any resolution, and on the
  image corpus the 7 documents where a rubber stamp covers the value, the QR code (which
  nothing here decodes) and full names that only exist split across MRZ lines. They are
  excluded rather than counted as clean — on the stamp documents that means the value
  under the stamp was neither redacted nor proven.
* Keep-list losses on the normal corpus are 5-digit CPT codes read as possible ZIPs
  and all-caps organisation headers — the safety-over-fidelity trade.
* Keep-list losses on the image corpus are the 7 stamped `PAID 09/22/2023` impressions,
  which tesseract reads below the confidence floor and the tool therefore redacts as
  `[UNCLEAR]`. Fail-closed, and the only thing lost.
* The image corpus is slow because verification is expensive: every page is OCR'd at
  300 dpi in **all four orientations** and the reads are unioned. Picking one "best"
  orientation is faster and was wrong — a value legible at the three dropped angles
  made the probe unverifiable, which looks exactly like clean.

### Proving the checker itself

A verifier that has quietly stopped detecting reports zero leaks and looks like a
triumphant result. So both hard corpora are also run **against their own inputs** —
the checker is pointed at the unredacted documents, where every single probe should
come back as a leak:

| corpus | docs | critical leaks found | unverifiable |
|---|---|---|---|
| `tricky` inputs | 12 | 964 (NAME 309, SSN 206, PHONE 202, ACCT 188, …) | 0 |
| `images` inputs | 12 | 170 (ADDRESS 56, NAME 42, SSN 16, IMAGE 12, …) | 11 |

Every surface fires: text, pdftotext, streams, annots, widgets, outline, attachments,
meta, XMP, pixels and image-bytes.

## What it caught

The first run of this harness failed **11 of 14** documents with 88 planted values
still present, while the tool's own self-check said `CLEAN`. Everything below came
out of it, and each has a regression test in `tests/test_regressions.py`:

1. **Label regexes were not grouped.** `^\s*{pat}\s*:?$` binds the anchors to the
   first/last alternative only, so any cell *containing* "reference"/"signer" was a
   name label — and a label swallows its value block.
2. **The image-OCR cache was shared across a batch** and keyed on `(xref, w, h)`.
   xref numbers restart in every file, so file B's picture got file A's words: those
   values were never marked, and unrelated words were burned. Silent, and only
   visible when redacting several files at once.
3. **Tesseract splits one visual line into two blocks** with ~0.2 pt of baseline
   jitter, so "DOB September 13, 1965" became two cells and "13, 1965" survived.
4. **A DOB cue redacted every date in the paragraph**, including service dates, once
   context was carried across wrapped lines.
5. **A name on the line under "Sincerely,"** is a separate text block: nothing
   carried the cue down, and the signer survived.
6. **Truncated emails** — "x.y@corp.e" cut by a screenshot edge — matched no email
   regex, so the local part stayed in the pixels.
7. **Names were only learned from labelled fields**, so a signer, a "requested by"
   clause or a "first.last@" address taught the tool nothing. It now learns from all
   three and catches bare mentions anywhere, including inside pictures.
8. **All-caps transaction lines** ("POS PURCHASE NORTHSIDE MARKET") were redacted as
   names once they repeated across the batch.
9. **A bare "REFERENCE" column header** read as a person label and swallowed the
   whole table under it, amounts included.

Then the tricky corpus, which found the class the page never shows:

10. **Annotations, form fields, bookmark titles and attachments** were not read at
    all. The SSN sat in a free-text note, the member ID in a form field, the name in
    a bookmark title, and a `.txt` attachment carried the lot — a copy that looked
    clean and shipped all of it.
11. **Text below the crop box** was invisible to PyMuPDF and visible to `pdftotext`,
    so the copy leaked to exactly the tools it is meant to feed.
12. **A 60-row table** was only half covered: the value-block cap was 20 cells, so
    rows 6-60 kept their names.

The image-only corpus then found three more, all in the same seam — a scan that is not
the right way up:

13. **A sideways sheet was read as noise, and signed off anyway.** Tesseract half-reads
    rotated text with high confidence (`COLDWATER MUTUAL` came back as `H3LVMA100
    TVNLNN`), so the page "had words", the orientation was never questioned, and the
    columns came out interleaved — every multi-word detector missed, `CLEAN` printed.
14. **Redaction rectangles were a quarter turn off.** Page coordinates are the
    *unrotated* ones; boxes taken from a render that had been turned upright put the
    black rectangles somewhere else entirely. Partial removal looks like removal.
15. **The rebuilt text layer smuggled the value back.** The rebuild skips words that
    were redacted *by object identity*; de-rotating the boxes created fresh tuples, so
    the pixels were burned and the value was written back as invisible text.

Two more, from the same run:

16. **A page nothing could be read from was reported as clean.** Fixed: unreadable
    pages are named and the run exits `2`.
17. **OCR noise in the copy counted as a residual pattern hit.** A wrong-orientation
    read of `COLDWATER` is `H3LVMA100`, which looks like an account number. Pattern
    hits now have to appear in the *input* too. The same rule is why the checker
    OCRs every orientation and unions the reads instead of picking a best one.

## Limits

* The corpus is synthetic: good at layouts and value shapes, blind to what a real
  bureau report does that nobody thought of here.
* The pixel checks depend on tesseract too. A value OCR cannot read is reported as
  unverifiable rather than passed — the count is in every report.
* Only planted values are scored. A category nobody planted is a category nobody
  checked.
* A barcode is not decoded, a signature is not read, and a rubber stamp over a value
  hides that value from the tool as effectively as it hides it from you. The `images`
  corpus plants all three so the gap is counted rather than assumed away.
