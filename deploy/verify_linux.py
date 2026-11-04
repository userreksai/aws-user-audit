#!/usr/bin/env python3
"""Check generated PDF/mail units in temporary files, without starting services."""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from install_support import render_units


def main():
    with tempfile.TemporaryDirectory(prefix="aws-audit-ci-") as temporary:
        root = Path(temporary)
        runtime, units = root / "runtime", root / "units"
        for folder in (runtime / ".venv/bin", runtime / "deploy", units):
            folder.mkdir(parents=True, exist_ok=True)
        (runtime / ".venv/bin/python").symlink_to(sys.executable)
        shutil.copyfile(Path(__file__).parent / "run_scheduled.py", runtime / "deploy/run_scheduled.py")
        for clock in ("10:05", "09:10"):
            rendered = render_units(str(runtime), config_path=str(runtime / "aws-audit-config.json"), daily_mail_time=clock)
            for name, content in rendered.items():
                (units / name).write_text(content, encoding="utf-8")
            subprocess.run(["systemd-analyze", "verify", str(units / "aws-user-audit.service"),
                            str(units / "aws-user-audit.timer")], check=True)
            calendar = next(line.removeprefix("OnCalendar=") for line in rendered["aws-user-audit.timer"].splitlines()
                            if line.startswith("OnCalendar="))
            subprocess.run(["systemd-analyze", "calendar", calendar], check=True)
        assert not (runtime / "index").exists()
    print("Generated PDF/mail units and Beijing calendars verified; no services started.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
