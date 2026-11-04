"""Cache public AWS Chinese reference pages for build_event_catalog.py.

This developer-only command needs internet access. Daily audit jobs use the
checked-in catalog and never execute this downloader.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import argparse
import re
from urllib.request import Request, urlopen

DOC_ROOT = "https://docs.aws.amazon.com/zh_cn/service-authorization/latest/reference/"


def fetch(name, directory):
    request = Request(DOC_ROOT + name, headers={"User-Agent": "AWS-audit-documentation-builder/1.0"})
    with urlopen(request, timeout=15) as response:
        data = response.read(5_000_001)
    if len(data) > 5_000_000:
        raise ValueError("Official document exceeds 5 MB")
    # Replace only after a complete response; partial downloads cannot overwrite
    # a previously usable document.
    temporary = directory / (name + ".tmp")
    temporary.write_bytes(data)
    temporary.replace(directory / name)
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path, default=Path("tmp/catalog-cache"))
    args = parser.parse_args()
    args.cache_dir.mkdir(parents=True, exist_ok=True)
    content = fetch("reference_policies_actions-resources-contextkeys.html", args.cache_dir).decode("utf-8")
    names = sorted(set(re.findall(r"list_[a-z0-9_-]+\.html", content)))
    if not names:
        raise SystemExit("AWS service index contained no document links")
    failed = 0
    with ThreadPoolExecutor(max_workers=8) as pool:
        pending = {pool.submit(fetch, name, args.cache_dir): name for name in names}
        for index, future in enumerate(as_completed(pending), 1):
            try:
                future.result()
            except (OSError, ValueError):
                failed += 1
                print("Failed: " + pending[future], flush=True)
            if index % 50 == 0 or index == len(names):
                print(f"Completed {index}/{len(names)}; failed {failed}", flush=True)
    if failed:
        raise SystemExit("Some documentation downloads failed; review cache before rebuilding")


if __name__ == "__main__":
    main()
