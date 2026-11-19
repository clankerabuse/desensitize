# NOTICE — third-party components used by desens-rs

## MuPDF (vendored headers + shared library)

- `thirdparty/mupdf-1.28.6-source/include/` — MuPDF 1.28.6 public headers,
  from https://mupdf.com/downloads/archive/mupdf-1.28.6-source.tar.gz
- `lib/libmupdf.so.28.6` — the unmodified shared library bundled inside the
  PyMuPDF wheel (`pymupdf/libmupdf.so.28.6`, built by the pymupdf-mupdf
  project from the same MuPDF source).

MuPDF is © Artifex Software, Inc., licensed under the **GNU Affero General
Public License v3** (with a commercial option). Desensitize links against it
dynamically and does not modify MuPDF; the full corresponding source for
MuPDF 1.28.6 is available at mupdf.com/downloads/archive, and this project's
own source (which contains no MuPDF-derived code) is MIT-licensed. Anyone
redistributing a binary of desens-rs together with libmupdf must comply with
the AGPL, including offering the MuPDF source.

The Python build has the same exposure through the PyMuPDF wheel.

## Regex engines

`fancy-regex` (MIT) backs the patterns needing lookarounds; `regex`
(MIT OR Apache-2.0) backs the rest.
