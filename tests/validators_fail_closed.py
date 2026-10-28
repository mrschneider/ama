"""F03 regression harness: every experiment validator must FAIL CLOSED.

The review reproduced experiment 008 printing FAIL while exiting 0 — a green
CI concealing broken guarantees. This harness extracts each script's Python
validator heredoc, runs it against an EMPTY ledger, and asserts the process
exits nonzero (tracebacks count: an exception is also a nonzero exit).

Run: python3 tests/validators_fail_closed.py
"""
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).parent.parent / "experiments"
SCRIPTS = sorted(HERE.glob("experiment_0*.sh"))


def validator_heredoc(script: Path) -> str | None:
    """The validator = the python3 heredoc whose body contains `def ok`.
    Scripts can carry several heredocs (PID helpers etc.), so scan them all."""
    s = script.read_text()
    for m in re.finditer(r"python3 - <<'(?:EOF|PYEOF)'\n(.*?)\n(?:EOF|PYEOF)\n", s, re.S):
        body = m.group(1)
        if "def ok" in body:
            return body
    return None


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--list":
        for s in SCRIPTS:
            print(s.name, "->", "validator" if validator_heredoc(s) else "no validator")
        return 0
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        empty = Path(tmp) / "ledger.jsonl"
        empty.write_text("")
        for script in SCRIPTS:
            body = validator_heredoc(script)
            if body is None:
                print(f"SKIP (no validator): {script.name}")
                continue
            body = body.replace("/tmp/ama_exp/", str(Path(tmp)) + "/")
            r = subprocess.run([sys.executable, "-c", body], capture_output=True, text=True)
            verdict = "PASS" if r.returncode != 0 else "FAIL-OPEN"
            if r.returncode == 0:
                failures.append(script.name)
            print(f"{verdict}: {script.name} exits {r.returncode} on empty evidence")
    if failures:
        print("\nFAIL-OPEN validators (print FAIL, exit 0):", failures)
        return 1
    print(f"\nAll {len(SCRIPTS)} validators fail closed on empty evidence.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
