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
from .verify import VerificationReport, scan_copy

__version__ = "0.1.0"

__all__ = [
    "redact",
    "scan_copy",
    "Redactor",
    "RedactionResult",
    "DocumentResult",
    "VerificationReport",
    "NoTextLayerError",
    "__version__",
]


def redact(paths, out_dir=None, names_file=None) -> RedactionResult:
    """Redact `paths` into `out_dir` (default: ~/Downloads/agent-friendly)."""
    out = out_dir or (Path.home() / "Downloads" / "agent-friendly")
    return Redactor(out_dir=out, names_file=names_file).redact(paths)
