# desens-rs — the Rust port of desens

Rust rewrite of `desens` (PII-redacted, agent-friendly copies of PDFs), on the
same MuPDF core the Python build uses. Same detectors, same exit-code
contract, same counts-only output.

**Status: milestone 1 of 3 — text-layer parity.** The Python build stays the
installed `desens` until the port reaches full coverage.

## Milestone map

| | done | notes |
|---|---|---|
| text-layer extraction | ✓ | stext walk, one `fz_context` per rayon worker, pages in parallel |
| detectors (patterns/detect/layout) | ✓ | byte-exact counts vs Python on the test corpus |
| destructive glyph redaction | ✓ | `pdf_redact_page` (PDF_REDACT_TEXT_REMOVE), same op pymupdf performs |
| metadata scrub | ✓ | info dict blanked, garbage=4 + deflate + clean save |
| annotation scrub | ✓ | contents + subject rewritten with typed placeholders |
| verify (self-check) | ✓ | pattern rescan + digest-token check + annot/field/outline reads |
| OCR (scans, orientation) | ✓ | tesseract subprocess, `OMP_THREAD_LIMIT=1`, pages in parallel |
| image regions on text pages | ✓ | "screenshot of a statement" case, pixels burned + re-scanned |
| visible `[LABEL]` placeholders | ✓ | drawn via content-stream text ops on every marked page |
| invisible text layer on scans | ✓ | kept OCR words written render-mode-3, so the copy extracts |
| form-field value rewrite | ✓ | detect-and-rewrite via field label fallback |
| unreadable pages | ✓ | ink + no strong words -> exit 2, "cannot be proven clean" |
| exit codes 0/1/2/3/4 | ✓ | 0 clean, 1 usage, 2 review/unproven, 3 scan+--ocr off, 4 no tesseract |
| annot titles, attachments, TOC rewrite | ✗ milestone 3 | no public MuPDF API; outline titles verified, not rewritten |
| distribution (static musl binary, wheels off) | ✗ milestone 3 | |

Milestone caveats are printed on every run and carried in `--report`, so a
consumer can never mistake partial coverage for full coverage.

## Build

Requires: rustc/cargo, a C compiler, and the vendored MuPDF bits (see NOTICE.md
for their origin and licence):

```
# once: fetch the header tarball (AGPL) and the shared library
curl -LO https://mupdf.com/downloads/archive/mupdf-1.28.6-source.tar.gz
mkdir -p thirdparty rust/lib
tar xzf mupdf-1.28.6-source.tar.gz -C rust/thirdparty   # headers, matched version
cp $(python -c 'import pymupdf,os;print(os.path.join(os.path.dirname(pymupdf.__file__),"libmupdf.so.28.6"))') rust/lib/

cargo build --release   # in rust/
./target/release/desens-rs file.pdf -o outdir
```

`build.rs` compiles `src/shim.c` (every throwing MuPDF call wrapped in
`fz_try`/`fz_catch`, so Rust never sees a longjmp), links the vendored
`libmupdf.so.28.6` and sets an rpath to `rust/lib`.

## Layout

- `src/shim.c` — the fz_try/fz_catch boundary; the only C in the project
- `src/ffi.rs` — minimal MuPDF FFI + the stext walker (pointer-chasing only)
- `src/patterns.rs` / `src/detect.rs` — ports of `patterns.py` / `detect.py`
- `src/layout.rs` / `src/engine.rs` / `src/verify.rs` — ports of the rest
- `src/main.rs` — CLI + parallel orchestration

## Parity + performance (this box, 16 cores)

- fake-credit-report corpus (2 pages): identical category counts to the
  Python build (ACCT 2, ADDRESS 7, DOB 1, EMAIL 1, EMPLOYER 2, NAME 13,
  NUMBER 2, PHONE 1, SSN 3), both exit 0 with CLEAN self-checks.
- 40-page text PDF: 0.29 s vs Python 1.09 s (3.8x); startup 2 ms vs 130 ms.
- scan input: refused with exit 3, matching the contract, until milestone 2.
