"""pdf-redact: agent-friendly, PII-redacted copies of PDF documents.

    from pdf_redact import redact

    result = redact(["statement.pdf"], out_dir="~/Downloads/agent-friendly")
    print(result.counts)          # Counter({'ADDRESS': 12, 'NAME': 9, ...})
    for doc in result.documents:
        print(doc.output)         # -> redacted copy, originals untouched
"""
from __future__ import annotations

from pathlib import Path

from .engine import (
    POLICY,
    DocumentResult,
    NoTextLayerError,
    RedactionResult,
    Redactor,
    resolve_policy,
)
from .ocr import OcrUnavailableError, ocr_page_words
from .verify import VerificationReport, ocr_rescan, scan_copy

__version__ = "0.8.0"

__all__ = [
    "redact",
    "scan_copy",
    "ocr_rescan",
    "ocr_page_words",
    "OcrUnavailableError",
    "Redactor",
    "POLICY",
    "resolve_policy",
    "RedactionResult",
    "DocumentResult",
    "VerificationReport",
    "NoTextLayerError",
    "__version__",
]


def redact(paths, out_dir=None, names_file=None, ocr="auto", dpi=300,
           min_conf=None, ocr_images=None) -> RedactionResult:
    """Redact `paths` into `out_dir` (default: ~/Downloads/agent-friendly).

    There is one coverage policy: text layer, scans, every embedded picture, and
    a pixel-level re-scan of the finished copy. `ocr="auto"` OCRs pages without a
    text layer; `"off"` refuses scans.
    """
    out = out_dir or (Path.home() / "Downloads" / "agent-friendly")
    return Redactor(out_dir=out, names_file=names_file, ocr=ocr, dpi=dpi,
                    min_conf=min_conf, ocr_images=ocr_images).redact(paths)
