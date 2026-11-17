"""Command line interface.

Prints category counts only -- never a value -- so the tool's own output is safe
to paste into a chat, an issue or a log.

Exit codes:
    0  clean: copies written, self-check found nothing
    1  bad usage / missing input
    2  review needed: the self-check still sees something in the copies
    3  input has no text layer (scanned PDF -- needs OCR, refused)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .engine import NoTextLayerError, Redactor
from .verify import scan_copy

DEFAULT_OUT = Path.home() / "Downloads" / "agent-friendly"


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="pdf-redact",
        description="Write PII-redacted, agent-friendly copies of PDFs "
                    "(SSN, address, phone, email, DOB, account IDs, names).",
    )
    ap.add_argument("inputs", nargs="+", help="PDF file(s) to copy-and-redact")
    ap.add_argument("-o", "--out", default=str(DEFAULT_OUT),
                    help=f"output directory (default: {DEFAULT_OUT})")
    ap.add_argument("--names", metavar="FILE",
                    help="extra names to always redact, one per line")
    ap.add_argument("--dry-run", action="store_true",
                    help="report what would be redacted, write nothing")
    ap.add_argument("--report", metavar="FILE",
                    help="write a JSON manifest of counts here")
    ap.add_argument("--debug-marks", action="store_true",
                    help="print each redaction mark (page, label, position)")
    ap.add_argument("-q", "--quiet", action="store_true", help="counts only, no banner")
    ap.add_argument("--version", action="version", version=f"pdf-redact {__version__}")
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    redactor = Redactor(out_dir=args.out, names_file=args.names)
    try:
        result = redactor.redact(args.inputs, dry_run=args.dry_run,
                                 debug_marks=args.debug_marks)
    except FileNotFoundError as exc:
        print(f"!! missing input: {exc}", file=sys.stderr)
        return 1
    except NoTextLayerError as exc:
        print(f"!! {exc}: no usable text layer (scanned PDF?) -- needs OCR, "
              f"refusing rather than pretending it is redacted.", file=sys.stderr)
        return 3

    if args.dry_run:
        for doc in result.documents:
            print(f"  {doc.source.name}: {doc.pages} pages")
            for cat, n in sorted(doc.counts.items()):
                print(f"      {cat:<9} {n}")
        print(f"  would redact {result.total} spans; nothing written (--dry-run)")
        return 0

    verifications = {}
    for doc in result.documents:
        verifications[doc.source.name] = scan_copy(
            doc.output, result.redacted_hashes, result.unredacted_vocab)

    if not args.quiet:
        print("== redaction summary (counts only, no values) ==")
        for doc in result.documents:
            print(f"  {doc.source.name}  ->  {doc.output.name}   ({doc.pages} pages)")
            for cat, n in sorted(doc.counts.items()):
                print(f"      {cat:<9} {n}")
        print("== self-check on the copies ==")

    clean = True
    for name, rep in verifications.items():
        if not args.quiet:
            hits = {k: v for k, v in rep.pattern_hits.items() if v}
            print(f"  {name}")
            print(f"    residual pattern hits: {hits or 'none'}")
            print(f"    residual re-detected known values: {rep.leak_total}")
            for cat, ln, masked in rep.masked_samples:
                print(f"      {cat:<9} {ln:>3}  {masked}")
        clean = clean and rep.clean

    if not args.quiet:
        print("  RESULT:", "CLEAN" if clean else "REVIEW NEEDED (see above)")

    if args.report:
        manifest = {
            "tool": f"pdf-redact {__version__}",
            "inputs": [str(d.source) for d in result.documents],
            "outputs": [
                {
                    "file": d.source.name,
                    "pages": d.pages,
                    "output": str(d.output),
                    "redactions_by_type": dict(d.counts),
                }
                for d in result.documents
            ],
            "redactions_total": result.total,
            "redactions_by_type": dict(result.counts),
            "verification": {k: v.as_dict() for k, v in verifications.items()},
            "clean": clean,
        }
        out = Path(args.report)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(manifest, indent=2))
        out.chmod(0o600)

    return 0 if clean else 2


if __name__ == "__main__":
    sys.exit(main())
