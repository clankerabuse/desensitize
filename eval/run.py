"""Run the whole loop: generate documents, redact them, verify independently.

    python eval/run.py --count 100 --seed 7      # fresh documents, one policy
    python eval/run.py                           # reuse the documents on disk

There is one coverage policy now (everything readable + pixel proof), so there is no
level to pass. Exit code 0 only when the independent verifier finds no critical leak
and no checker error.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = str(ROOT / ".venv" / "bin" / "python")
CLI = str(ROOT / ".venv" / "bin" / "pdf-redact")


def arg(argv, flag, default=None):
    return argv[argv.index(flag) + 1] if flag in argv else default


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    data = Path(arg(argv, "--data", str(ROOT / "eval" / "data")))
    count = arg(argv, "--count", "40")
    seed = arg(argv, "--seed", "7")
    dpi = arg(argv, "--dpi", "300")
    regen = "--regen" in argv or not (data / "truth.json").exists()

    if regen:
        print(f"== generating {count} documents (seed {seed}) ==")
        subprocess.run([PY, str(ROOT / "eval" / "gen.py"), str(data),
                        "--count", count, "--seed", seed], check=True)

    docs = sorted((data / "docs").glob("*.pdf"))
    out_dir = data / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n== redacting {len(docs)} documents ==")
    proc = subprocess.run([CLI, *map(str, docs), "-o", str(out_dir),
                           "--report", str(data / "manifest.json"), "-q"],
                          capture_output=True, text=True)
    print(f"  pdf-redact: exit {proc.returncode}")
    if proc.returncode not in (0, 2):
        print(proc.stdout[-2000:], proc.stderr[-3000:])
        return proc.returncode
    print(f"  tool self-check: {'CLEAN' if proc.returncode == 0 else 'REVIEW NEEDED'}")

    print("\n== independent verification ==")
    return subprocess.run([PY, str(ROOT / "eval" / "check.py"), str(data),
                           str(out_dir), "--dpi", dpi,
                           "--json", str(data / "report.json")],
                          text=True).returncode


if __name__ == "__main__":
    sys.exit(main())
