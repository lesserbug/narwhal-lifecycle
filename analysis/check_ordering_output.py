"""Check whether primary output traces have comparable certificate prefixes."""

import argparse
import json
from pathlib import Path


def outputs(path: Path) -> list[str]:
    digests = []
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            event = json.loads(line)
            if event.get("event") == "CertificateCommitted":
                digests.append(event["certificate_digest"])
    return digests


def common_prefix(left: list[str], right: list[str]) -> int:
    return next(
        (i for i, (a, b) in enumerate(zip(left, right)) if a != b),
        min(len(left), len(right)),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("traces", nargs="+", type=Path, help="primary-*.jsonl files")
    args = parser.parse_args()

    traces = {path.stem: outputs(path) for path in args.traces}
    names = sorted(traces)
    if len(names) < 2:
        parser.error("at least two primary traces are required")

    for name in names:
        sequence = traces[name]
        print(json.dumps({"primary": name, "outputs": len(sequence),
                          "duplicate_outputs": len(sequence) - len(set(sequence))}))

    for i, left_name in enumerate(names):
        for right_name in names[i + 1:]:
            left, right = traces[left_name], traces[right_name]
            prefix = common_prefix(left, right)
            print(json.dumps({"left": left_name, "right": right_name,
                              "common_prefix": prefix,
                              "diverged": prefix < min(len(left), len(right))}))


if __name__ == "__main__":
    main()
