"""pdf-redact: agent-friendly, PII-redacted copies of PDF documents.

    from pdf_redact import redact

    result = redact(["statement.pdf"], out_dir="~/Downloads/agent-friendly")
    print(result.counts)          # Counter({'ADDRESS': 12, 'NAME': 9, ...})
    for doc in result.documents:
        print(doc.output)         # -> redacted copy, originals untouched
"""
from __future__ import annotations

from pathlib import Path

from .engine import DocumentResult, NoTextLayerError, RedactionResult, Redactor
from .ocr import OcrUnavailableError, ocr_page_words
from .verify import VerificationReport, ocr_rescan, scan_copy

__version__ = "0.3.0"

__all__ = [
    "redact",
    "scan_copy",
    "ocr_rescan",
    "ocr_page_words",
    "OcrUnavailableError",
    "Redactor",
    "RedactionResult",
    "DocumentResult",
    "VerificationReport",
    "NoTextLayerError",
    "__version__",
]


def redact(paths, out_dir=None, names_file=None, ocr="auto", dpi=300,
           min_conf=60.0, ocr_images=True) -> RedactionResult:
    """Redact `paths` into `out_dir` (default: ~/Downloads/agent-friendly).

    `ocr="auto"` OCRs any page without a text layer, and by default also OCRs
    embedded images that could hide text of their own; `"off"` refuses scans.
    """
    out = out_dir or (Path.home() / "Downloads" / "agent-friendly")
    return Redactor(out_dir=out, names_file=names_file, ocr=ocr, dpi=dpi,
                    min_conf=min_conf, ocr_images=ocr_images).redact(paths)
