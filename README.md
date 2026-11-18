# desensitize

`desens` makes **agent-friendly copies** of sensitive PDFs — credit reports, bank
statements, tax forms, insurance letters — by deleting the personal data and replacing
it with typed placeholders. Text PDFs lose the glyphs; scans — and pictures embedded in
text PDFs — lose the pixels (and get a clean text layer of their own).

```bash
desens ~/Downloads/creditReport_1234.pdf
# -> ~/Downloads/agent-friendly/creditReport_redacted.pdf
```

```
== redaction summary (full coverage + pixel proof; counts only, no values) ==
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

`desens` does the two things that actually matter:

1. **It deletes the glyphs** (`PyMuPDF` redaction annotations + `apply_redactions`), so
   text extraction, copy-paste and `pdftotext` all come back empty.
2. **It proves it worked** — the copies are re-opened and re-scanned, and the tool
   exits non-zero if anything sensitive survived.

## Install

```bash
uv pip install "git+https://github.com/clankerabuse/desensitize"
# or, from a clone
uv pip install -e ".[dev]"
```

Requires Python 3.9+ and PyMuPDF (bundled wheels). For scanned PDFs you also need
tesseract plus a language pack — `pacman -S tesseract tesseract-data-eng` on Arch,
`apt install tesseract-ocr` on Debian. Without it, text PDFs still work and scans are
refused with a clear error.

## Usage

```bash
desens report.pdf                      # redact into ~/Downloads/agent-friendly
desens a.pdf b.pdf -o ~/safe           # several files, one output dir
desens report.pdf --dry-run            # counts only, writes nothing
desens report.pdf --names people.txt   # force these names to be redacted
desens report.pdf --report manifest.json
desens report.pdf --debug-marks        # where each mark landed (page/x/y)
desens scan.pdf --ocr force            # scan wrapped in a junk text layer
```

| Exit | Meaning |
|---|---|
| `0` | copies written, self-check clean |
| `1` | bad usage / missing input |
| `2` | **review needed** — the self-check or the pixel re-scan still sees something |
| `3` | scan and `--ocr off` — refused rather than faked |
| `4` | OCR requested but tesseract (or the language pack) is missing |

Output directory is `0700`, copies are `0600`, and PDF metadata (title/author/producer)
is stripped as well.

### For agents

The skill ships in this repo at `skills/pdf-desensitize/`: it teaches an agent to
desensitize first, read only the copy, print counts never values, and treat a non-zero
exit as "do not hand this over".

```bash
# Hermes: fetch the whole bundle (SKILL.md + references/)
hermes skills install clankerabuse/desensitize/skills/pdf-desensitize

# ...or make the repo a skill source and search it
hermes skills tap add clankerabuse/desensitize

# Any other SKILL.md agent (Claude Code, Cursor, Codex)
cp -r skills/pdf-desensitize ~/.claude/skills/

# Repo-local for Hermes in a checkout: put it under .hermes/skills/ and run
hermes skills trust
```

## Scanned PDFs (OCR)

Scans are a different problem: there is no text to delete, the ink **is** the document.
So for a scanned page `desens`:

1. renders it (300 dpi by default) and runs **local** tesseract — no upload, no API,
   the language model is a file on disk (`unshare -rn tesseract …` works);
2. runs the same detectors over OCR words, which carry per-word confidence — any word
   below `--min-conf` (default 80) is redacted as `[UNCLEAR]` rather than guessed at,
   and the OCR detectors tolerate glyph confusions (`0/O`, `1/I/l`, `5/S`, `8/B`) so
   an SSN read as `512-84-993I` still matches;
3. burns the pixels under each redaction (`PDF_REDACT_IMAGE_PIXELS`) — measured on a
   real page: the SSN's box went from 33% ink to 0%;
4. writes a **new invisible text layer** containing only the surviving words, so the
   copy still extracts as text and the ordinary self-check verifies a layer we built
   rather than hoping OCR round-trips.

The pixel proof is always on and is the only check that can catch a rendering-level
mistake: it OCRs the finished copy again and looks for the redacted values in the
pixels, limited to the pages and boxes that were actually OCR'd.

### A scan is not always the right way up

A sheet goes into a feeder sideways, or upside down, and the scan comes out that way.
Tesseract will *half-read* rotated text — it returns `H3LVMA100 TVNLNN` for
`COLDWATER MUTUAL` with confidences in the 90s — so "it found words" is no evidence
that the page was read the right way up. Worse, the half-read page comes back with its
columns interleaved, which breaks every multi-word detector while the tool reports a
clean copy.

So every scanned page is oriented first: tesseract's orientation detector is asked,
the page is read at that rotation, and if the result does not look like prose the other
three rotations are tried and scored. Scoring is on **legible characters**, not word
count, because confident garbage scores high on word count. Word boxes are then mapped
back through `derotation_matrix` — page coordinates are the *unrotated* ones, and a
rectangle taken straight from the turned render lands a quarter turn away.

### A page nothing could be read from is not a clean page

An unreadable scan (too small, too blurred, too faint) yields no words. That used to be
indistinguishable from a blank page, and the run said `CLEAN`. Now a page with ink on
it that OCR could not read is reported per page and the run exits `2` — `REVIEW NEEDED`
— because nothing about that page was proven. Blank sheets stay clean.


## Coverage: everything readable, then proof

There is one policy, not a ladder. It used to have `--level fast|default|full|paranoid`;
the ladder is gone, because a level that skipped a pasted ID card covering 0.19% of a
page produced a copy that *looked* exactly like a clean one.

So every run does all of this:

| Reads | Then proves it |
|---|---|
| the text layer; pages with none (OCR); every picture on a text page down to 8×4 pt / 64 px; OCR words below confidence 80 | the copy's text layer, plus a second OCR pass over every page and picture box that was touched |

Cost on two real credit reports (25 + 12 pages): 3.5 s to read the text and
document-sized pictures, 4.3 s once the icon-sized ones are included, 6.0 s with the
pixel proof. The whole 40-document synthetic corpus in `eval/` takes 13 s.

The proof is the part that matters for scans: the copy's text layer is written by us,
so reading it back proves consistency, not safety. The re-scan reads the **pictures**
and fails the run (exit 2) if anything redacted is still legible in them. It only
re-OCRs what was OCR'd the first time, so a text-only document pays nothing.

Three knobs remain, for when you know better than the default:

```bash
desens tax.pdf --min-conf 60          # accept shakier OCR words
desens tax.pdf --no-ocr-images        # text layer only -- and then nothing
                                          # proves what was in the pictures
desens scan.pdf --ocr force           # a scan wrapped in a junk text layer
```

## Objects that are not on the page

Half of a PDF is not the page. Every run also reads, and scrubs:

* **annotations** — free-text notes, sticky notes, comment subjects. The text is
  redacted in place; an annotation that cannot be rewritten is dropped;
* **form fields** — a text field's value is PII like any other. It is replaced with
  a typed placeholder, and the field's *name* is used as its label
  (`cardholder_name`, `member_id`) when the value carries no other context;
* **bookmark titles** — replaced whole (`[REDACTED]`) when they match, because half a
  title still names the person and nobody needs the rest to navigate;
* **attached files** — dropped, and counted as `ATTACHMENT`: an attachment is a
  second document the tool cannot see into;
* **text outside the visible box** — a crop strip or "gone" footer is read too,
  because `pdftotext` reads it even though a reader does not. The page keeps its
  original crop on the copy.

## Pictures inside text PDFs

A statement can carry a text layer *and* a pasted screenshot of another statement. OCR
is therefore **on by default** for embedded images too:

* `page.get_image_info()` lists the pictures on a page cheaply — no rendering, no OCR —
  so the tool knows where to look before spending anything;
* only pictures below 8×4 pt or 64 source pixels are skipped — below that there is not
  enough area for a glyph to survive, and a real report's spacer tiles and rules live
  there (one report had 26 such per page);
* each surviving region is rendered and OCR'd on its own, its words are placed in
  absolute page coordinates, and they go through the same detectors as normal text;
* identical images are OCR'd once and shifted into place — a header logo repeated on
  12 pages costs one tesseract call;
* because those words live in pixels, the page is redacted with pixel smearing, not
  glyph deletion.

```bash
desens statement.pdf                  # text + every picture
desens statement.pdf --no-ocr-images  # text layer only, and nothing is proven
```

Cost on two real credit reports (25 + 12 pages): 4.3 s, of which ~1 s is the one logo
the xref cache did not have to redo.

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
3. **Names** — learned from labelled fields (`Consumer Name:`, `Patient:`, `Borrower`,
   `Also Known As:`), from the local part of a `first.last@` address, and from
   salutations/signature lines ("Dear …,", "Sincerely, …", "requested by …"). A bare
   mention of a learned name is then caught anywhere on the page, including in a
   header, a footer, prose and a picture. 2/3-token capitalised runs that occur **twice
   or more across the inputs** are also treated as names, unless the run is
   organisation vocabulary or an all-caps heading/transaction line — a real name
   repeats, but "POS PURCHASE NORTHSIDE MARKET" repeats too and is not a person.
   `--names` gives you a hard override.
4. **Apply** — redaction annotations over exactly the affected words, `apply_redactions`
   to delete the glyphs, then a small red `[LABEL]` placeholder at the same spot.
5. **Verify** — the copies are re-read: value regexes are re-run, and every redacted
   value's SHA-256 digest is compared against the copy's tokens — text layer, OCR'd
   pixels, annotations, form-field values and bookmark titles. Generic words that
   legitimately remain elsewhere are filtered out so real leaks are not drowned out.

Library use:

```python
from desensitize import redact, scan_copy

result = redact(["statement.pdf"], out_dir="~/safe")
print(result.counts)                                   # Counter({'SSN': 1, ...})
report = scan_copy(result.documents[0].output,
                   result.redacted_hashes, result.unredacted_vocab)
print(report.clean)                                    # True
```

## Limitations (read these)

* **Scanned PDFs depend on OCR accuracy.** A value tesseract misreads badly enough can
  slip past the detectors; that is why the confidence floor, the confusable-glyph
  patterns and the pixel proof exist. For high-stakes scans, review the copy — a page
  it could not read at all is reported as `REVIEW NEEDED` rather than signed off.
* **A barcode is not read.** A QR code holding an SSN is pixels nothing here decodes.
  The page is still scanned by eye-OCR (which sees a block of noise), so treat a
  document with codes as unverified by this tool.
* **Handwriting is not read.** A cursive signature or a handwritten note is a picture
  of ink: tesseract will not recover it, and the tool does not pretend to. Printed text
  on the same page is redacted normally.
* **Tiny pictures are still ignored.** Below 8×4 pt / 64 source pixels nothing is
  examined — there is not enough area for a glyph to survive, but it is a floor, not a
  promise.
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

`eval/` is the larger harness. It generates 40 synthetic documents across 14
archetypes — credit reports, W-2s, statements, insurance letters, invoices, medical
bills, leases, scans, pasted screenshots, dark-mode captures, a rotated card — with a
ground-truth manifest of every planted value, runs the tool over the batch, then
re-derives leaks from the copies on four independent surfaces (text layer,
`pdftotext`, OCR'd pixels, decompressed content streams) plus a byte-hash check on
every embedded picture. `python eval/run.py --count 40` prints the
scorecard; see `eval/README.md`.

## Licence

MIT.
