# pdf-redact

Make **agent-friendly copies** of sensitive PDFs — credit reports, bank statements,
tax forms, insurance letters — by deleting the personal data and replacing it with
typed placeholders. Text PDFs lose the glyphs; scanned PDFs — and pictures embedded in
text PDFs — lose the pixels (and get a clean text layer of their own).

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
pdf-redact report.pdf --level full         # also OCR icon-sized pictures
pdf-redact scan.pdf --level paranoid       # full coverage + prove the pixels are clean
pdf-redact scan.pdf --ocr force            # scan wrapped in a junk text layer
```

| Exit | Meaning |
|---|---|
| `0` | copies written, self-check clean |
| `1` | bad usage / missing input |
| `2` | **review needed** — the self-check (or the paranoid pixel re-scan) still sees something |
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

`--verify-deep` (implied by `--level paranoid`) adds the only check that can catch a
rendering-level mistake: it OCRs the finished copy again and looks for the redacted
values in the pixels, limited to the pages and boxes that were actually OCR'd.

## Levels: how much gets looked at

One flag sets the coverage policy. Each step only *adds* sources — the text layer is
always read first — so a higher level never detects less of your text.

| `--level` | Reads | Then proves it | Real pair of credit reports |
|---|---|---|---|
| `fast` | text layer + pages with no text | text layer | 2.5 s, 0 image regions |
| `default` | + pictures ≥ 40×12 pt and ≥ 0.5% of the page | text layer | 3.5 s, 12 regions (1 OCR) |
| `full` | + every picture ≥ 8×4 pt / 64 px, confident-only OCR words | text layer | 4.3 s, 15 regions |
| `paranoid` | same as `full` | + re-OCRs the pixels that were touched | 6.0 s |

`full` and `paranoid` raise the OCR confidence floor from 60 to 80, so shaky words
become `[UNCLEAR]` instead of being read optimistically.

`paranoid` is the one that closes the loop on scans: the copy's text layer is written
by us, so scanning it proves consistency, not safety — this level re-OCRs every page
or image box that was touched and fails the run (exit 2) if anything redacted is still
readable in the picture. It only OCRs what was OCR'd the first time, so a text-only
document pays nothing and a report with 15 logo regions pays ~1 s.

Anything set explicitly still wins:

```bash
pdf-redact tax.pdf --level full --min-conf 55     # full coverage, my threshold
pdf-redact tax.pdf --level fast --ocr-images      # fast, but still look at pictures
```

If you don't know which to pick: `default`. Reach for `full` when the document may hide
IDs in icons or cropped screenshots, `paranoid` when the input is a scan you cannot
eyeball afterwards, and `fast` when you are batching thousands of clean digital
statements.

## Pictures inside text PDFs

A statement can carry a text layer *and* a pasted screenshot of another statement. OCR
is therefore **on by default** for embedded images too:

* `page.get_image_info()` lists the pictures on a page cheaply — no rendering, no OCR —
  so the tool knows where to look before spending anything;
* images smaller than ~40×12 pt, under 0.5% of the page area, or under 5 000 source
  pixels are skipped as logos, icons, rules and spacer tiles (a real report had 26 of
  those per page);
* each surviving region is rendered and OCR'd on its own, its words are placed in
  absolute page coordinates, and they go through the same detectors as normal text;
* identical images are OCR'd once and shifted into place — a header logo repeated on
  12 pages costs one tesseract call;
* because those words live in pixels, the page is redacted with pixel smearing, not
  glyph deletion.

```bash
pdf-redact statement.pdf                  # text + images (default level)
pdf-redact statement.pdf --no-ocr-images  # text layer only, faster
pdf-redact statement.pdf --level full     # icon-sized pictures too
```

Cost on two real credit reports (25 + 12 pages): 3.5 s at the default level, of which
~1 s is the one logo the xref cache did not have to redo.

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
* **Small images are skipped unless you ask.** At `default` the tool ignores pictures
  below 40×12 pt or 0.5% of the page; `--level full` drops that floor to 8×4 pt / 64 px.
  Below *that* nothing is examined — a face with an ID number printed at 3 pt would be
  missed no matter the level.
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
