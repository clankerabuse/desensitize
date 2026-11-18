# eval — does the redaction actually remove the data?

A synthetic benchmark for `pdf-redact`. It builds documents whose sensitive values
are **known**, runs the tool over them, then looks for those values in the copies
from four independent surfaces. The checker shares no code with the tool: if the
two disagree, the checker is right.

```
python eval/run.py --count 100 --seed 7       # generate, redact, verify
python eval/run.py --regen --count 100        # fresh documents
python eval/run.py --dpi 400                  # sharper pixel check, slower
```

There is one coverage policy, so there is no level to choose.

Everything lands in `eval/data/`: `docs/` (the inputs), `truth.json` (every planted
value, the probes used to look for it, the keep-list, and a sha256 per picture),
`out/` (the copies), `manifest.json` (the tool's own report) and `report.json` (the
independent verdict). `run.py` exits non-zero if any
critical leak survives.

## The documents

Fourteen archetypes, cycled to N files: credit report (2 pp, account table, section
headers), bank statement (2 pp, ledger, wire instructions), W-2 (boxed form), insurance
letter (prose, salutation, signature block, cc), invoice, medical bill, lease
application (references, employer, signature), utility bill, a pure **scan**
(rasterised pages), a text page with a pasted **screenshot**, a page with a normal
**ID-card crop** and an **icon-sized one**, a **dark-mode** screenshot, a page with
**90°-rotated text and a rotated image**, and a 3-page record with the identity in a
**header and footer**.

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

Before scoring, every probe is looked for in the **input**. A probe the checker
cannot find there (a 6 pt ID in a 58×16 pt crop that tesseract cannot read) is
reported as *unverifiable* and excluded, so a blind spot in the checker can never be
mistaken for a clean document.

## Results

100 documents in one batch — 130 pages, 1 336 planted values, 779 keep-list strings,
52 embedded pictures, 4 pure scans (14 archetypes):

| failing documents | critical leaks | soft leaks | keep-list intact | tool time |
|---|---|---|---|---|
| 0 / 100 | 0 | 0 | 704/779 (90%) | 32 s |

2 097 redactions were applied, including 2 `[UNCLEAR]` (OCR words below the confidence
floor, redacted rather than guessed). The tool's own `--report` self-check agrees
(`clean: true`, exit 0). Redaction plus the full independent verification takes 2 m 34 s;
the eval is the slow half, because it OCRs every page of every copy again.

Six probes are unverifiable: truncated email addresses inside pasted screenshots
(`x.y@corp.e`, cut by the image edge) that the checker cannot find in the *input*
either. The name in the local part is still scored, and was caught.

What is left in the keep-list losses: 5-digit CPT codes swallowed as possible ZIPs,
and a few masked tails — the deliberate "safety over fidelity" trade.

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

## Limits

* The corpus is synthetic: good at layouts and value shapes, blind to what a real
  bureau report does that nobody thought of here.
* The pixel checks depend on tesseract too. A value OCR cannot read is reported as
  unverifiable rather than passed — the count is in every report.
* Only planted values are scored. A category nobody planted is a category nobody
  checked.
