#!/usr/bin/env python3
"""Check generated units and Nginx syntax in temporary files, without starting services."""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from install_support import render_units
from nginx_config import prepare_text


def main():
    with tempfile.TemporaryDirectory(prefix="aws-audit-ci-") as temporary:
        root = Path(temporary)
        runtime, public, units = root / "runtime", root / "public", root / "units"
        for folder in (runtime / ".venv/bin", runtime / "deploy", public, units, root / "logs"):
            folder.mkdir(parents=True, exist_ok=True)
        (runtime / ".venv/bin/python").symlink_to(sys.executable)
        shutil.copyfile(Path(__file__).parent / "run_scheduled.py", runtime / "deploy/run_scheduled.py")
        for name, content in render_units(str(runtime), str(public), "audit", str(runtime / "lark-config.json")).items():
            (units / name).write_text(content, encoding="utf-8")
        subprocess.run(["systemd-analyze", "verify", str(units / "aws-user-audit.service"),
                        str(units / "aws-user-audit.timer")], check=True)
        subprocess.run(["systemd-analyze", "calendar", "*-*-* 08:01:00 Asia/Shanghai"], check=True)
        frontend = """location / {
        proxy_pass http://127.0.0.1:8890;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }"""
        rds_routes = """location = /audit_rds { return 302 /audit_rds/; }
    location ^~ /audit_rds/ { alias /srv/example-rds-report/; index index.html; autoindex off; }"""
        original = """server {
    listen 8889;
    server_name zybocedata-pass.v668live.com;
    absolute_redirect off;
    location = /audit { return 302 /audit/; }
    location ^~ /audit/ { proxy_pass http://127.0.0.1:9998; }
    """ + frontend + "\n    " + rds_routes + "\n}\n"
        candidate = prepare_text(original, "zybocedata-pass.v668live.com", 8889, str(public))
        assert frontend in candidate
        assert rds_routes in candidate
        assert "127.0.0.1:9998" not in candidate
        (root / "site.conf").write_text(candidate, encoding="utf-8")
        (root / "nginx.conf").write_text(
            f'pid "{root}/nginx.pid";\nerror_log stderr;\nevents {{ worker_connections 64; }}\n'
            + f'http {{ access_log off; include "{root}/site.conf"; }}\n', encoding="utf-8")
        subprocess.run(["nginx", "-t", "-e", "stderr", "-p", str(root) + "/", "-c", str(root / "nginx.conf")], check=True)
    print("Generated units, calendar, and isolated Nginx syntax verified; no services started.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
