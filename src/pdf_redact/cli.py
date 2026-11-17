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
from .ocr import DEFAULT_DPI, DEFAULT_LANG, DEFAULT_MIN_CONF, OcrUnavailableError
from .verify import ocr_rescan, scan_copy

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
    ap.add_argument("--ocr", choices=["auto", "force", "off"], default="auto",
                    help="OCR pages without a text layer: auto (default), force every "
                         "page, or off (refuse scans)")
    ap.add_argument("--dpi", type=int, default=DEFAULT_DPI,
                    help=f"render resolution for OCR (default {DEFAULT_DPI})")
    ap.add_argument("--ocr-lang", default=DEFAULT_LANG,
                    help=f"tesseract language (default {DEFAULT_LANG})")
    ap.add_argument("--min-conf", type=float, default=DEFAULT_MIN_CONF,
                    help="OCR words below this confidence are redacted as [UNCLEAR] "
                         f"(default {DEFAULT_MIN_CONF})")
    ap.add_argument("--ocr-images", dest="ocr_images", action="store_true", default=True,
                    help="OCR embedded images on otherwise-textual pages (default: on)")
    ap.add_argument("--no-ocr-images", dest="ocr_images", action="store_false",
                    help="skip embedded images (text layer only)")
    ap.add_argument("--verify-deep", action="store_true",
                    help="also re-OCR the copies and look for leaks in the pixels "
                         "(slow, recommended for scans)")
    ap.add_argument("--debug-marks", action="store_true",
                    help="print each redaction mark (page, label, position)")
    ap.add_argument("-q", "--quiet", action="store_true", help="counts only, no banner")
    ap.add_argument("--version", action="version", version=f"pdf-redact {__version__}")
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    redactor = Redactor(out_dir=args.out, names_file=args.names, ocr=args.ocr,
                        dpi=args.dpi, lang=args.ocr_lang, min_conf=args.min_conf,
                        ocr_images=args.ocr_images)
    try:
        result = redactor.redact(args.inputs, dry_run=args.dry_run,
                                 debug_marks=args.debug_marks)
    except FileNotFoundError as exc:
        print(f"!! missing input: {exc}", file=sys.stderr)
        return 1
    except NoTextLayerError as exc:
        print(f"!! {exc}: scanned PDF and --ocr off, refusing rather than "
              f"pretending it is redacted.", file=sys.stderr)
        return 3
    except OcrUnavailableError as exc:
        print(f"!! OCR unavailable: {exc}", file=sys.stderr)
        return 4

    if args.dry_run:
        for doc in result.documents:
            print(f"  {doc.source.name}: {doc.pages} pages")
            for cat, n in sorted(doc.counts.items()):
                print(f"      {cat:<9} {n}")
        print(f"  would redact {result.total} spans; nothing written (--dry-run)")
        return 0

    verifications = {}
    for doc in result.documents:
        report = scan_copy(doc.output, result.redacted_hashes, result.unredacted_vocab)
        if args.verify_deep and doc.ocr_pages:
            # the text layer is ours on a scan; check the pixels too
            deep = ocr_rescan(doc.output, result.redacted_hashes,
                              result.unredacted_vocab, lang=args.ocr_lang)
            report.pattern_hits.update(deep.pattern_hits)
            report.leak_total += deep.leak_total
            report.leaks_by_category.update(deep.leaks_by_category)
            report.masked_samples.extend(deep.masked_samples[:25])
        verifications[doc.source.name] = report

    if not args.quiet:
        print("== redaction summary (counts only, no values) ==")
        for doc in result.documents:
            tag = ""
            if doc.ocr_pages:
                tag += f", {doc.ocr_pages} OCR page(s)"
            if doc.image_regions:
                tag += f", {doc.image_regions} image region(s)"
            print(f"  {doc.source.name}  ->  {doc.output.name}   "
                  f"({doc.pages} pages, {doc.mode}{tag})")
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
            "outputs": [d.as_dict() for d in result.documents],
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
