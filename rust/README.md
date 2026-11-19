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
| exit codes 0/1/2/3 | ✓ | 0 clean, 1 usage, 2 review, 3 scan refused |
| OCR (scans, image regions) | ✗ milestone 2 | scans are refused (exit 3) rather than faked |
| visible `[LABEL]` placeholders on page | ✗ milestone 2 | annots already get typed placeholders |
| form-field value rewrite | ✗ milestone 2 | values are verified (exit 2 on leak), never rewritten |
| annot titles, attachments, TOC rewrite | ✗ milestone 2/3 | outline titles verified; titles/attachments not checkable via public API yet |

Milestone-1 caveats are printed on every run and carried in `--report`, so a
consumer can never mistake partial coverage for the Python build's full proof.

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
