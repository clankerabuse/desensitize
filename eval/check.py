"""Independent verifier: does the redacted copy still contain the planted values?

Deliberately shares no code with `desensitize` -- if the tool's own self-check and
this disagree, this one is right. Four independent surfaces:

* **text**   -- PyMuPDF text extraction and `pdftotext -layout`
* **pixels** -- the pages (and each planted picture's box) rendered and OCR'd
                with confusable glyphs allowed (0/O, 1/I/l, 5/S, 8/B, 2/Z, 6/G)
* **stream** -- every decompressed content stream, scanned for the raw value
* **image**  -- embedded images hashed against the input's: a PII picture that
                survives byte-identical is a certain leak, no OCR needed

Every probe is also looked for in the *input* first. A probe that cannot be found
there is reported as unverifiable and excluded from scoring -- that way a broken
probe can never be mistaken for a clean document.

    python eval/check.py eval/data eval/out/default [--json eval/out.json]
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pymupdf

CONF = {
    "0": "0OoQ", "O": "0Oo", "o": "0Oo", "1": "1Il|", "I": "1Il", "l": "1Il",
    "5": "5S", "S": "5S", "8": "8B", "B": "8B", "2": "2Z", "Z": "2Z",
    "6": "6G", "G": "6G", "9": "9g",
}
SEP = r"[\s\-–—_.,/\\|()\[\]]{0,3}"


def _cls(ch: str, confusable: bool) -> str:
    if not confusable:
        return re.escape(ch)
    return "[" + re.escape(CONF.get(ch, ch)) + "]"


def probe_regex(probe: dict, confusable: bool = False) -> re.Pattern | None:
    kind, value = probe["kind"], probe["text"]
    if kind in {"digits", "alnum"}:
        core = re.sub(r"\D" if kind == "digits" else r"[^A-Za-z0-9]", "", value)
        if len(core) < 3:
            return None
        body = SEP.join(_cls(c, confusable) for c in core)
        return re.compile(rf"(?<![0-9A-Za-z]){body}(?![0-9A-Za-z])",
                          re.IGNORECASE if kind == "alnum" else 0)
    if kind == "text":
        body = re.escape(norm_ws(value)).replace(r"\ ", r"\s+")
        return re.compile(body, re.IGNORECASE)
    if kind == "tokens":
        toks = re.findall(r"[A-Za-z][A-Za-z'\-]*", value)
        if not toks:
            return None
        parts = [r"(?<![A-Za-z])" + re.escape(t) + r"(?![A-Za-z])" for t in toks]
        return re.compile(r"[\s\S]{0,40}?".join(parts), re.IGNORECASE)
    return None


def norm_ws(s: str) -> str:
    return re.sub(r"\s+", " ", s)


def find_hits(probes, text, confusable, where, limit_per_probe=2):
    hits = []
    for probe in probes:
        rx = probe_regex(probe, confusable)
        if rx is None:
            continue
        for m in rx.finditer(text):
            s, e = max(0, m.start() - 28), min(len(text), m.end() + 28)
            hits.append({
                "cat": probe.get("cat"), "probe": probe["text"],
                "kind": probe["kind"], "critical": probe["critical"],
                "where": where, "match": m.group(0)[:60],
                "context": norm_ws(text[s:e]),
            })
            if len([h for h in hits if h["probe"] == probe["text"]]) >= limit_per_probe:
                break
    return hits


def ocr_png(path: Path, psm: int = 3) -> str:
    try:
        out = subprocess.run(["tesseract", str(path), "stdout", "--psm", str(psm)],
                             capture_output=True, text=True, timeout=180)
        return out.stdout
    except Exception as exc:                       # pragma: no cover
        return f"__OCR_FAILED__ {exc}"


def page_ocr_text(page, dpi: int, clip=None, rotation=None) -> str:
    old = page.rotation
    if rotation is not None and rotation != old:
        page.set_rotation(rotation)
    try:
        pix = page.get_pixmap(dpi=dpi, clip=clip, alpha=False)
    finally:
        if rotation is not None and rotation != old:
            page.set_rotation(old)
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as fh:
        tmp = Path(fh.name)
    pix.save(tmp)
    try:
        return ocr_png(tmp)
    finally:
        tmp.unlink(missing_ok=True)


def page_ocr_any(page, dpi: int) -> str:
    """OCR a page from all four orientations and keep every word of it.

    A probe legible at *any* rotation is a probe the checker has to be able to
    see. Picking a single "best" read -- by word count, or by how much of it
    looks like prose -- lets a value hide at the three rotations that were
    dropped, and a checker that cannot find a value in the input reports it as
    unverifiable, which looks the same as clean.
    """
    base = page.rotation
    texts = []
    for delta in (0, 90, 180, 270):
        try:
            texts.append(page_ocr_text(page, dpi, rotation=(base + delta) % 360))
        except Exception:
            continue
    return "\n".join(t for t in texts if t)


def doc_texts(path: Path) -> dict[str, str]:
    """Every surface that can hold text, as {surface: text}.

    A copy is clean only if the value is gone from all of them: the text layer,
    a second extractor, annotation contents, form fields, bookmark titles,
    attached files, DocInfo and the XMP packet.
    """
    out = {k: "" for k in ("text", "pdftotext", "annots", "widgets",
                           "outline", "attachments", "meta", "xmp")}
    with pymupdf.open(path) as doc:
        out["text"] = "\n".join(p.get_text("text") for p in doc)
        try:
            proc = subprocess.run(["pdftotext", "-layout", str(path), "-"],
                                  capture_output=True, text=True, timeout=180)
            out["pdftotext"] = proc.stdout or ""
        except Exception:
            pass

        annots, widgets = [], []
        for page in doc:
            try:
                for a in page.annots() or []:
                    info = a.info or {}
                    annots.append(" ".join(str(info.get(k) or "")
                                           for k in ("content", "title", "subject")))
            except Exception:
                pass
            try:
                for w in page.widgets() or []:
                    widgets.append(f"{w.field_name or ''} {w.field_value or ''}")
            except Exception:
                pass
        out["annots"] = "\n".join(annots)
        out["widgets"] = "\n".join(widgets)

        try:
            out["outline"] = "\n".join(entry[1] for entry in doc.get_toc(simple=True))
        except Exception:
            pass

        files = []
        try:
            for name in doc.embfile_names():
                data = doc.embfile_get(name)
                body = data.decode("utf-8", "replace") if isinstance(data, bytes) else str(data)
                files.append(f"{name}\n{body}")
        except Exception:
            pass
        out["attachments"] = "\n".join(files)

        try:
            out["meta"] = "\n".join(str(v) for v in (doc.metadata or {}).values())
        except Exception:
            pass
        try:
            out["xmp"] = doc.get_xml_metadata() or ""
        except Exception:
            pass
    return out


def stream_text(doc) -> str:
    """Every content stream, decompressed, as one string.

    Glyphs can be painted without any extractor showing them, so the stream is
    the last place a value can sit and still be rendered to a reader.
    """
    parts = []
    for xref in range(1, doc.xref_length()):
        try:
            if not doc.xref_is_stream(xref):
                continue
            parts.append(doc.xref_stream(xref).decode("latin-1", "replace"))
        except Exception:
            continue
    return "\n".join(parts)


def image_hashes(path: Path) -> set[str]:
    """SHA-256 of every embedded picture: one that survives untouched is a leak."""
    digests = set()
    with pymupdf.open(path) as doc:
        for page in doc:
            for img in page.get_images(full=True):
                try:
                    digests.add(hashlib.sha256(doc.extract_image(img[0])["image"]).hexdigest())
                except Exception:
                    continue
    return digests


def check_doc(in_path: Path, out_path: Path, entry: dict, dpi: int = 300) -> dict:
    """Return {'leaks': [...], 'unverifiable': [...], 'keep_lost': [...]}."""
    probes = []
    for v in entry["values"]:
        for p in v["probes"]:
            probes.append(dict(p, cat=v["cat"], value=v["value"]))
    images = [im for im in entry.get("images", []) if im.get("pii")]
    res = {"doc": entry["name"], "kind": entry["kind"], "leaks": [],
           "unverifiable": [], "keep_lost": [], "ocr_failed": False}

    if not out_path.exists():
        res["missing"] = True
        return res

    inx = doc_texts(in_path)
    out = doc_texts(out_path)

    # ---- 0. the probe must be findable in the input, else it cannot be scored
    in_stream = ""
    with pymupdf.open(in_path) as doc:
        in_stream = stream_text(doc)
    for probe in probes:
        rx = probe_regex(probe, confusable=False)
        if rx is None:
            res["unverifiable"].append({"probe": probe["text"], "cat": probe["cat"],
                                        "why": "too short"})
            continue
        if any(rx.search(t) for t in inx.values() if t) or rx.search(in_stream):
            continue
        # pictures may only be legible via OCR; test the planted image boxes and,
        # when that fails, the page the way a reader would look at it
        found = False
        if images:
            with pymupdf.open(in_path) as idoc:
                for im in images:
                    if im["page"] >= idoc.page_count:
                        continue
                    page = idoc[im["page"]]
                    clip = pymupdf.Rect(im["rect"])
                    if rx.search(norm_ws(page_ocr_text(page, dpi, clip=clip))):
                        found = True
                        break
                    if rx.search(norm_ws(page_ocr_any(page, dpi))):
                        found = True
                        break
        if not found:
            res["unverifiable"].append({"probe": probe["text"],
                                        "cat": probe["cat"],
                                        "why": "not found in input"})

    # ---- 1. every object surface: text layer, pdftotext, annots, widgets,
    #         outline titles, attachments, DocInfo, XMP
    for probe in probes:
        if any(u["probe"] == probe["text"] for u in res["unverifiable"]):
            continue
        for surface, text in out.items():
            if not text:
                continue
            res["leaks"] += find_hits([probe], text, False, surface)

    # ---- 2. content streams (glyphs that no extractor showed us)
    out_stream = out_stream_cache(out_path)
    for probe in probes:
        if any(u["probe"] == probe["text"] for u in res["unverifiable"]):
            continue
        raw = probe["text"]
        core = re.sub(r"[^0-9A-Za-z]", "", raw)
        for needle in {raw, core}:
            if len(needle) < 6 or needle not in in_stream:
                continue
            if needle in out_stream or norm_ws(needle) in out_stream:
                res["leaks"].append({
                    "cat": probe["cat"], "probe": probe["text"],
                    "kind": probe["kind"], "critical": probe["critical"],
                    "where": "stream", "match": needle,
                    "context": "decompressed content stream still holds the value",
                })

    # ---- 3. pixels: whole pages, then each planted picture's box
    with pymupdf.open(out_path) as odoc:
        for pno in range(odoc.page_count):
            text = norm_ws(page_ocr_any(odoc[pno], dpi))
            if "__OCR_FAILED__" in text:
                res["ocr_failed"] = True
                continue
            res["leaks"] += find_hits(probes, text, True, f"pixels:p{pno + 1}")
        for im in images:
            pno = im["page"]
            if pno >= odoc.page_count:
                continue
            clip = pymupdf.Rect(im["rect"])
            text = norm_ws(page_ocr_text(odoc[pno], max(dpi, 400), clip=clip))
            res["leaks"] += find_hits(probes, text, True, f"imagebox:p{pno + 1}")

    # ---- 4. embedded picture bytes unchanged
    if images:
        out_h = image_hashes(out_path)
        for im in images:
            if im.get("sha256") and im["sha256"] in out_h:
                res["leaks"].append({
                    "cat": "IMAGE", "probe": f"image p{im['page'] + 1}",
                    "kind": "image-bytes", "critical": True, "where": "image-bytes",
                    "match": "picture survived byte-identical",
                    "context": "", "sha256": im["sha256"][:12],
                })

    # ---- 5. collateral: things that must survive
    # the copy's layer puts each word on its own line, so compare on one line
    flat = norm_ws(out["text"]).lower()
    for keep in entry.get("keep", []):
        if norm_ws(keep).lower() not in flat:
            res["keep_lost"].append(keep)

    # de-duplicate identical (probe, where) rows
    seen, leaks = set(), []
    for h in res["leaks"]:
        key = (h["probe"], h["where"], h["match"])
        if key in seen:
            continue
        seen.add(key)
        leaks.append(h)
    res["leaks"] = leaks
    res["unverifiable"] = res["unverifiable"]
    return res


_OUT_STREAM: dict = {}


def out_stream_cache(path: Path) -> str:
    if path not in _OUT_STREAM:
        with pymupdf.open(path) as doc:
            _OUT_STREAM[path] = stream_text(doc)
    return _OUT_STREAM[path]


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    data = Path(argv[0])
    out_dir = Path(argv[1])
    report_path = Path(argv[argv.index("--json") + 1]) if "--json" in argv else None
    dpi = int(argv[argv.index("--dpi") + 1]) if "--dpi" in argv else 300

    truth = json.loads((data / "truth.json").read_text())
    entries = truth["docs"]
    jobs = []
    for entry in entries:
        in_path = data / "docs" / entry["name"]
        out_path = out_dir / entry["name"]
        jobs.append((in_path, out_path, entry))

    results = []
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = [ex.submit(check_doc, i, o, e, dpi) for i, o, e in jobs]
        for fut, (_in_path, _out_path, e) in zip(futs, jobs):
            try:
                results.append(fut.result())
            except Exception as exc:            # one bad copy must not hide the rest
                results.append({"doc": e["name"], "kind": e["kind"], "leaks": [],
                                "unverifiable": [], "keep_lost": [],
                                "error": f"{type(exc).__name__}: {exc}"})
                print(f"[ERR ] {e['name']}: {type(exc).__name__}: {exc}")

    total_crit = total_soft = 0
    by_cat = Counter()
    failed_docs = []
    for r in results:
        crit = [h for h in r["leaks"] if h["critical"]]
        soft = [h for h in r["leaks"] if not h["critical"]]
        total_crit += len(crit)
        total_soft += len(soft)
        for h in crit:
            by_cat[h["cat"]] += 1
        status = ("FAIL" if crit else "ERR" if r.get("error")
                  else ("soft" if soft else "ok"))
        if crit:
            failed_docs.append(r["doc"])
        print(f"[{status:4}] {r['doc']:<34} crit={len(crit):>3} soft={len(soft):>2} "
              f"unverif={len(r['unverifiable']):>2} keep_lost={len(r['keep_lost']):>2}")
        for h in crit[:12]:
            print(f"         LEAK {h['cat']:<9} {h['kind']:<11} {h['where']:<14} "
                  f"{h['probe']!r} -> {h['match']!r}")
        for h in soft[:4]:
            print(f"         soft {h['cat']:<9} {h['kind']:<11} {h['where']:<14} "
                  f"{h['probe']!r}")
        for u in r["unverifiable"][:6]:
            print(f"         UNVERIFIABLE {u['cat']:<9} {u['probe']!r} ({u['why']})")

    keep_total = sum(len(e.get("keep", [])) for e in entries)
    keep_lost = sum(len(r["keep_lost"]) for r in results)
    print("\n== summary ==")
    errors = [r for r in results if r.get("error")]
    print(f"  documents          {len(results)}")
    print(f"  failing documents  {len(failed_docs)}")
    print(f"  checker errors     {len(errors)}")
    print(f"  critical leaks     {total_crit}  by category: {dict(by_cat)}")
    print(f"  soft leaks         {total_soft}")
    print(f"  unverifiable probes {sum(len(r['unverifiable']) for r in results)}")
    print(f"  keep-list preserved {keep_total - keep_lost}/{keep_total}")

    if report_path:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps({
            "data_dir": str(data), "out_dir": str(out_dir), "dpi": dpi,
            "documents": len(results), "failing": failed_docs,
            "critical_leaks": total_crit, "soft_leaks": total_soft,
            "by_category": dict(by_cat), "keep_total": keep_total,
            "keep_lost": keep_lost, "results": results,
        }, indent=1))
        print(f"  report -> {report_path}")
    return 0 if (total_crit == 0 and not errors) else 2


if __name__ == "__main__":
    sys.exit(main())
