# pdf-redact

Make **agent-friendly copies** of sensitive PDFs — credit reports, bank statements,
tax forms, insurance letters — by deleting the personal data and replacing it with
typed placeholders. Text PDFs lose the glyphs; scanned PDFs lose the pixels (and get
a clean text layer of their own).

```bash
pdf-redact ~/Downloads/creditReport_1234.pdf
# -> ~/Downloads/agent-friendly/creditReport_redacted.pdf
```

```
== redaction summary (counts only, no values) ==
  creditReport_1234.pdf  ->  creditReport_redacted.pdf   (12 pages)
      NAME      170
      ADDRESS    51
      NUMBER     38
      PHONE      13
      ACCT        7
      ZIP         3
      SSN         1
      DOB         1
== self-check on the copies ==
  residual pattern hits: none
  residual re-detected known values: 0
  RESULT: CLEAN
```

The original is opened read-only. The copy is what you hand to a model, paste into a
chat, or attach to a ticket.

## Why this exists

Handing a document to an LLM means handing over every name, SSN, address and account
number in it. Most "redaction" people do before that is a black rectangle drawn *over*
the text — which does nothing: the glyphs are still in the content stream and any
extraction tool reads them straight back out.

`pdf-redact` does the two things that actually matter:

1. **It deletes the glyphs** (`PyMuPDF` redaction annotations + `apply_redactions`), so
   text extraction, copy-paste and `pdftotext` all come back empty.
2. **It proves it worked** — the copies are re-opened and re-scanned, and the tool
   exits non-zero if anything sensitive survived.

## Install

```bash
uv pip install "git+https://github.com/clankerabuse/pdf-redact"
# or, from a clone
uv pip install -e ".[dev]"
```

Requires Python 3.9+ and PyMuPDF (bundled wheels). For scanned PDFs you also need
tesseract plus a language pack — `pacman -S tesseract tesseract-data-eng` on Arch,
`apt install tesseract-ocr` on Debian. Without it, text PDFs still work and scans are
refused with a clear error.

## Usage

```bash
pdf-redact report.pdf                      # redact into ~/Downloads/agent-friendly
pdf-redact a.pdf b.pdf -o ~/safe           # several files, one output dir
pdf-redact report.pdf --dry-run            # counts only, writes nothing
pdf-redact report.pdf --names people.txt   # force these names to be redacted
pdf-redact report.pdf --report manifest.json
pdf-redact report.pdf --debug-marks        # where each mark landed (page/x/y)
pdf-redact scan.pdf --verify-deep          # re-OCR the copy's pixels, not just its text
pdf-redact scan.pdf --ocr force            # scan wrapped in a junk text layer
```

| Exit | Meaning |
|---|---|
| `0` | copies written, self-check clean |
| `1` | bad usage / missing input |
| `2` | **review needed** — the self-check still sees something in the copies |
| `3` | scan and `--ocr off` — refused rather than faked |
| `4` | OCR requested but tesseract (or the language pack) is missing |

Output directory is `0700`, copies are `0600`, and PDF metadata (title/author/producer)
is stripped as well.

## Scanned PDFs (OCR)

Scans are a different problem: there is no text to delete, the ink **is** the document.
So for a scanned page `pdf-redact`:

1. renders it (300 dpi by default) and runs **local** tesseract — no upload, no API,
   the language model is a file on disk (`unshare -rn tesseract …` works);
2. runs the same detectors over OCR words, which carry per-word confidence — any word
   below `--min-conf` (default 60) is redacted as `[UNCLEAR]` rather than guessed at,
   and the OCR detectors tolerate glyph confusions (`0/O`, `1/I/l`, `5/S`, `8/B`) so
   an SSN read as `512-84-993I` still matches;
3. burns the pixels under each redaction (`PDF_REDACT_IMAGE_PIXELS`) — measured on a
   real page: the SSN's box went from 33% ink to 0%;
4. writes a **new invisible text layer** containing only the surviving words, so the
   copy still extracts as text and the ordinary self-check verifies a layer we built
   rather than hoping OCR round-trips.

`--verify-deep` adds the only check that can catch a rendering-level mistake: it OCRs
the finished copy again and looks for the redacted values in the pixels. Slow (one
more OCR pass), worth it for anything that matters.

## What gets redacted

| Placeholder | Covers |
|---|---|
| `[NAME]` | consumer name, AKA/former names, name variants, bare surname mentions |
| `[SSN]` | full SSNs, already-masked ones (`XXX-XX-1234`), and bare 9-digit forms |
| `[ADDRESS]` | street lines, PO boxes, and dense city/state/ZIP lines |
| `[ZIP]` | ZIP and ZIP+4 |
| `[PHONE]` | phone, fax, mobile, cell numbers |
| `[EMAIL]` | email addresses |
| `[DOB]` | date **and** year of birth |
| `[EMPLOYER]` | employer / employment block |
| `[ACCT]` | account, member, file, reference, case, licence, passport, routing IDs |
| `[NUMBER]` | other long numeric IDs, confirmation numbers, `#2756` / `XXXX1234` tails |

Deliberately **kept**, because it is what you want to analyse: creditor names, account
type, responsibility, status, balances, limits, payment history, dates opened/updated,
dispute text. The point is a document that is still *useful*, not a blank page.

## How it works

1. **Layout** — each page's words are grouped into "cells" (text runs separated by wide
   horizontal gaps), so a label in column 1 and its value in column 2 are handled
   separately and a table row is not swallowed whole.
2. **Detection** — per cell: `Label: value` prefixes, then value regexes (SSN, email,
   phone, address, ZIP, long IDs), then DOB context, then learned names, then
   whole-cell address lines, then capitalised person-name candidates.
3. **Names** — learned from labelled fields (`Consumer Name:`, `Also Known As:`) and from
   2/3-token capitalised runs that occur **twice or more across the inputs** (a real
   name repeats in headers; a random proper noun does not). Company vocabulary is
   excluded so creditor names survive. `--names` gives you a hard override.
4. **Apply** — redaction annotations over exactly the affected words, `apply_redactions`
   to delete the glyphs, then a small red `[LABEL]` placeholder at the same spot.
5. **Verify** — the copies are re-read: value regexes are re-run, and every redacted
   value's SHA-256 digest is compared against the copy's tokens. Generic words that
   legitimately remain elsewhere are filtered out so real leaks are not drowned out.

Library use:

```python
from pdf_redact import redact, scan_copy

result = redact(["statement.pdf"], out_dir="~/safe")
print(result.counts)                                   # Counter({'SSN': 1, ...})
report = scan_copy(result.documents[0].output,
                   result.redacted_hashes, result.unredacted_vocab)
print(report.clean)                                    # True
```

## Limitations (read these)

* **Scanned PDFs depend on OCR accuracy.** A value tesseract misreads badly enough can
  slip past the detectors; that is why the confidence floor, the confusable-glyph
  patterns and `--verify-deep` exist. For high-stakes scans, review the copy.
* **Text inside an embedded image in an otherwise-textual PDF is not examined.** A
  screenshot pasted into a statement page is still a picture — OCR it explicitly
  (`--ocr force`) if you suspect one.
* **Names are heuristic.** A person's name that appears exactly once, in an unlabelled
  position, can survive. Use `--names` when it matters; the copies are cheap to redo.
* **Name repetition is measured across the whole run.** Redacting a batch of related
  documents catches more names than redacting them one at a time (a name that appears
  once per file is weaker evidence than twice in one run).
* **Over-redaction is intentional** in ambiguous spots — occasionally a creditor or a
  dwelling type ("Single family") gets caught. Safety over fidelity.
* **Not a legal redaction tool.** For discovery, court filings or FOIA releases, use a
  tool with human review and audit logging. This is for "don't paste my SSN into a
  chatbot", which is a real problem with a lower bar.
* The self-check proves *nothing the detectors look for* survived. It cannot prove a
  category nobody thought of is absent.

## Development

```bash
uv venv && uv pip install -e ".[dev]"
.venv/bin/python -m pytest      # fixture PDFs are generated, never committed
.venv/bin/ruff check .
```

Tests build a synthetic report in a temp directory (fake names, fake SSNs) that
reproduces the layouts that broke earlier versions: section headers whose values sit
below them, multi-column name rows, table rows with far-right values, an address split
across cells, masked SSNs, and `#1234` identifier tails.

## Licence

MIT.
