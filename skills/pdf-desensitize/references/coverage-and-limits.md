# Coverage, limits and proof

What `desens` examines, what it deliberately keeps, and what it cannot promise — read
before you tell a user a copy is "clean".

## One policy, every run

There is no level flag. Every run reads all of these and then proves each one:

| Reads | Proved by |
|---|---|
| text layer of every page | re-running the detectors on the copy |
| pages with no text layer (local tesseract at 300 dpi) | a second OCR pass over the copy's pixels |
| every picture on a text page down to 8x4 pt / 64 px | pixel re-scan of the boxes that were touched |
| OCR words below confidence 80 -> `[UNCLEAR]` | same re-scan |
| annotations, form fields, bookmark titles, attachments, text outside the crop box | re-read of the copy |

The self-check compares SHA-256 digests of the removed values against everything the
copy still extracts, so "nothing found" means the actual values are gone, not just that
no regex fired.

## What gets replaced

| Placeholder | Covers |
|---|---|
| `[NAME]` | consumer name, AKAs, variants, bare surname mentions |
| `[SSN]` | full, already-masked (`XXX-XX-1234`) and bare 9-digit forms |
| `[ADDRESS]` | street lines, PO boxes, dense city/state/ZIP lines |
| `[ZIP]` | ZIP and ZIP+4 |
| `[PHONE]` | phone, fax, mobile |
| `[EMAIL]` | email addresses |
| `[DOB]` | date and year of birth |
| `[EMPLOYER]` | employer / employment block |
| `[ACCT]` | account, member, file, reference, case, licence, passport, routing IDs |
| `[NUMBER]` | other long numeric IDs, confirmation numbers, `#2756` tails |
| `[ATTACHMENT]` | attached files (dropped: a second document it cannot see into) |

Kept on purpose because it is the analysis value: creditor names, account type,
responsibility, status, balances, limits, payment history, dates opened/updated, dispute
text. A useful document, not a blank one.

## Cannot promise

- **OCR misreads.** A value tesseract mangles past recovery can escape; the confidence
  floor and confusable-glyph detectors narrow this, they do not close it.
- **Barcodes, QR codes, handwriting.** Nothing decodes or reads these; the page is
  pixels. Treat such a document as unverified.
- **Tiny pictures** below 8x4 pt / 64 px are skipped by design (no room for a glyph) —
  a floor, not a promise.
- **A unique name in an unlabelled position.** Repetition across the run, label context
  and salutations are the evidence; one mention can survive.
- **Categories nobody thought of.** The self-check proves nothing the detectors look for
  survived. It cannot prove an unmodelled category is absent.
- **Legal/forensic use.** Not a discovery or FOIA tool; human review and audit logging
  are out of scope.

## Verify a run yourself (when the user wants evidence)

```bash
pdfinfo original.pdf  | grep Pages      # page counts must match
pdftotext copy.pdf -  | grep -En '[0-9]{9}|@|[0-9]+ [A-Z][a-z]+ (St|Ave|Rd)' ; echo "hits: $?"
```

Render two pages (`pdftoppm -r 100 -f 1 -l 2 copy.pdf /tmp/pg`) and look at them: layout
intact, identifiers unreadable, no stacked `[ADDRESS][ADDRESS]` placeholders. Do this on
the copy, never on the original.

## Regenerate the tool's own proof

```bash
cd ~/Projects/desensitize
.venv/bin/ruff check . && .venv/bin/python -m pytest -q      # 72 tests, synthetic PDFs
.venv/bin/python eval/run.py --count 40                      # 100-doc corpus scorecard
```

The eval harness builds synthetic documents with a ground-truth manifest, runs the tool,
then re-derives leaks from the copies on four independent surfaces (text layer,
`pdftotext`, OCR'd pixels, decompressed content streams). Nonzero `critical leaks` is a
regression in the tool, not in the document.
