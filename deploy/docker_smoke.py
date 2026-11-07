"""Exercise the built production image with fictional SDK/SMTP transports only."""
from datetime import datetime, timezone
from email.parser import BytesParser
from email.policy import default
from pathlib import Path
import os
import sys
from unittest.mock import Mock, patch

sys.path.insert(0, "/app")
from audit_config import load_config
from aws_audit_multi import run_report

CONFIG = "/usr/local/aws-user-audit/aws-audit-config.json"
ACTOR = "beiou"


class FakeTrail:
    def __init__(self, account):
        self.account = account

    def lookup_events(self, **kwargs):
        import json
        if kwargs["LookupAttributes"][0]["AttributeKey"] != "ReadOnly":
            return {"Events": []}
        rows = []
        for index, (source, name) in enumerate((("ec2", "ModifyInstanceAttribute"),
                                                 ("q", "SendMessage"))):
            row = {"eventID": f"smoke-{self.account}-{index}", "eventTime": "2026-11-04T04:15:00Z",
                   "eventSource": source + ".amazonaws.com", "eventName": name,
                   "recipientAccountId": self.account, "readOnly": False, "awsRegion": "eu-north-1",
                   "userIdentity": {"type": "IAMUser", "userName": ACTOR,
                                    "arn": f"arn:aws:iam::{self.account}:user/{ACTOR}"},
                   "requestParameters": {"password": "SMOKE_EVENT_SECRET"}, "responseElements": {}}
            rows.append({"EventId": row["eventID"], "CloudTrailEvent": json.dumps(row)})
        return {"Events": rows}


class FakeSession:
    region_name = "eu-north-1"

    def __init__(self, **kwargs):
        self.account = kwargs["aws_access_key_id"].removeprefix("SMOKE-")

    def client(self, service, **kwargs):
        if service == "sts":
            client = Mock()
            client.get_caller_identity.return_value = {"Account": self.account}
            return client
        if service == "cloudtrail":
            return FakeTrail(self.account)
        raise AssertionError("Unexpected AWS client")


def main():
    global ACTOR
    config = load_config(CONFIG)
    target = Path(config["OUTPUT_DIRECTORY"]) / "smoke.eml"
    smtp = Mock()
    smtp.ehlo.return_value = (250, b"OK")
    def accept(message, **kwargs):
        target.write_bytes(message.as_bytes())
        return {}
    smtp.send_message.side_effect = accept
    clock = datetime(2026, 11, 5, 2, 5, tzinfo=timezone.utc)
    with patch("boto3.Session", FakeSession), patch("audit_mail.smtplib.SMTP_SSL", return_value=smtp), \
         patch("aws_daily_audit.Pacer", return_value=lambda: None), \
         patch("lark_notify._send_payload", side_effect=AssertionError("Lark not expected")):
        assert run_report(config, "2026-11-05", send_mail=True, automatic_mail=True, now=clock) == 0
        published = Path(config["PUBLISH_DIRECTORY"]) / "index.html"
        first = published.read_text(encoding="utf-8")
        assert all(account in first for account in ("000000000001", "000000000002"))
        assert "beiou" in first and "SMOKE_EVENT_SECRET" not in first
        if os.name == "posix":
            assert published.stat().st_mode & 0o777 == 0o644
        # Change the fixture's actor to prove the persistent page is replaced,
        # while the existing automatic email receipt still prevents another mail.
        ACTOR = "newest-smoke-actor"
        # A rebuilt/restarted container must retain the same mail allowance.
        assert run_report(config, "2026-11-05", send_mail=True, automatic_mail=True, now=clock) == 0
        latest = published.read_text(encoding="utf-8")
        assert "newest-smoke-actor" in latest and "beiou" not in latest
        assert list(published.parent.glob("*.html")) == [published]
        assert {path.suffix for path in published.parent.iterdir()} <= {".html", ".css", ".js"}
    smtp.send_message.assert_called_once()
    message = BytesParser(policy=default).parsebytes(target.read_bytes())
    assert len(list(message.iter_attachments())) == 2
    html = message.get_body(preferencelist=("html",)).get_content()
    assert html.count("<table ") == 2 and "beiou" in html and "弹性IP申请/绑定" in html
    assert "SMOKE_EVENT_SECRET" not in target.read_text(encoding="utf-8")
    assert all(part.get_payload(decode=True).startswith(b"%PDF-") for part in message.iter_attachments())
    print("Offline container audit/PDF/HTML-email/latest HTML overwrite/persistent mail receipt verified.")


if __name__ == "__main__":
    main()
