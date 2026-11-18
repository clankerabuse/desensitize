---
name: pdf-desensitize
description: "Use when an agent must read a PDF that holds PII."
version: 1.0.0
author: Hermes Agent
license: MIT
platforms: [linux, macos]
metadata:
  hermes:
    tags: [pdf, pii, privacy, redaction, desensitize, ocr, statements, credit-report]
    category: productivity
---

# PDF Desensitize (`desens`)

Handing a PDF to a model hands over every SSN, address, account number and name inside
it. `desens` writes a copy with those values destroyed — glyphs deleted from the text
layer, pixels burned on scans — then re-opens its own output and proves nothing it
removed survived.

**Read the copy, never the original.** That single rule is the whole point of the tool.

## When to Use

- The user hands over a statement, credit report, tax form, invoice, insurance or
  medical PDF and asks for it summarised, extracted or analysed.
- "Redact this", "sanitise these", "make an agent-friendly copy", "don't let the model
  see my details".
- A document is about to go into a chat, a ticket, an issue, a model context or a gist.
- Not for court filings, discovery or FOIA releases — those need human legal review;
  say so instead of running the tool and calling it done.

## How to Work

1. `command -v desens` first. If missing, either the checkout at `~/Projects/desensitize`
   (`.venv/bin/desens`) or `uv pip install "git+https://github.com/clankerabuse/desensitize"`.
2. **Do not open, extract or OCR the original yourself.** Run the tool, then work only
   from the copy it writes (default `~/Downloads/agent-friendly/`).
3. **Print counts, never values.** The tool's summary is counts-only and safe to paste;
   make your own output match it.
4. Read the **exit code** before using anything. Only `0` means the copy is usable.

```bash
command -v desens || uv pip install "git+https://github.com/clankerabuse/desensitize"
desens creditReport_1234.pdf    # -> ~/Downloads/agent-friendly/creditReport_redacted.pdf
                                #    (4+ digit runs are stripped from the filename too)
desens a.pdf b.pdf -o ~/safe         # one call for related docs = better name recall
desens file.pdf --dry-run            # counts only, writes nothing
desens file.pdf --report run.json    # counts-only manifest, no values
desens file.pdf --names people.txt   # force names the detectors doubted
desens scan.pdf --ocr force          # a scan wrapped in a junk text layer
desens big.pdf --debug-marks         # where each mark landed (page/x/y)
```

Output dir is `0700`, copies `0600`, originals are opened read-only, PDF metadata is
stripped. Everything examined is examined locally — OCR is tesseract on disk, no
upload.

Library use (batch jobs, pipelines):

```python
from desensitize import redact, scan_copy
result = redact(["statement.pdf"], out_dir="~/safe")
print(result.counts)          # Counter({'SSN': 1, ...}) -- counts, never values
report = scan_copy(result.documents[0].output,
                   result.redacted_hashes, result.unredacted_vocab)
print(report.clean)           # True only when the copy is proven clean
```

## Exit Codes Are the Contract

| Exit | Meaning | What you do |
|---|---|---|
| `0` | copies written, self-check AND pixel re-scan clean | use the copy |
| `1` | bad usage / missing input | fix the command |
| `2` | **review needed** — something survived in the copies | do not hand it over; read the per-page report, fix input (`--names`), rerun, or tell the user that page needs a human |
| `3` | scan with `--ocr off` — refused rather than faked | rerun without `--ocr off` |
| `4` | tesseract or its language pack missing | install it (`pacman -S tesseract tesseract-data-eng`, `apt install tesseract-ocr`), then rerun |

A non-zero exit is not a warning to work around. Never "just read the original this
time" and never quietly drop the file.

## Before the Copy Leaves Your Hands

- Exit `0` and the summary line `RESULT: CLEAN` (both, not one).
- Anything you quote from the copy has no 9-digit runs, no emails, no street addresses.
- The **output filename** is sanitised too — IDs hide in names like
  `creditReport_6320581239.pdf`; rename the copy if needed.
- Originals untouched: the tool never writes to their paths, so leave them that way.

## Pitfalls That Cost Real Leaks

- **Scans are OCR-bound.** A badly misread value can slip the detectors — that is why
  the confidence floor and the pixel proof exist. For high-stakes scans, skim the copy.
- **A page nothing could be read from is not a clean page.** Unreadable ink is reported
  per page and exits `2`; blank sheets still exit `0`.
- **Barcodes/QR and handwriting are not read.** A code holding an SSN is pixels to this
  tool — say the document is unverified rather than saying it is clean.
- **Names are heuristic.** A name appearing once, unlabelled, can survive. Redact related
  documents in **one call** (repetition is counted across the run) and use `--names`
  when the identity page matters. The copies are cheap to redo.
- **Over-redaction is deliberate** — a creditor or a dwelling type occasionally goes.
  Safety over fidelity; do not "fix" it by lowering coverage.
- **`--no-ocr-images` makes a run look clean by examining less.** Only use it when the
  user explicitly accepts that pictures go unproven.
- **`--dry-run` writes nothing** — do not go looking for output copies afterwards.
- Pasting the summary from memory instead of the actual run output defeats the counts-only
  guarantee.

Coverage details, what is kept on purpose, and the can't-do list:
`references/coverage-and-limits.md`. Regenerating the tool's own proof (eval harness and
tests) is documented there too.
