"""Compare approved anonymous evaluation records; never execute candidates or score evidence."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


class Invalid(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Invalid(message)


def fields(obj, names):
    require(isinstance(obj, dict) and obj.keys() == set(names.split()), "invalid record fields")


def unique(pairs):
    obj = dict(pairs)
    require(len(obj) == len(pairs), "duplicate JSON key")
    return obj


def blob(path):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as f:
        require(stat.S_ISREG(os.fstat(fd).st_mode), "expected regular file")
        data = f.read(4 * 1024 * 1024 + 1)
        require(0 < len(data) <= 4 * 1024 * 1024, "invalid file size")
        return data


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest(value):
    require(isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value), "invalid digest")


def indexed(rows):
    require(isinstance(rows, list) and rows, "empty case list")
    result = {}
    for row in rows:
        key = row["case_id"]
        require(isinstance(key, str) and re.fullmatch("C[0-9]{3,8}", key), "invalid case ID")
        require(key not in result, "duplicate case")
        result[key] = row
    return result


def summarize(rows):
    tasks = [r for r in rows if r["expected"] == "pass"]
    solved = sum(r["accepted"] and r["observed"] == "pass" for r in tasks)
    costs = [r["cost_usd_micros"] for r in rows if r["cost_usd_micros"] is not None]
    return dict(solved=solved, tasks=len(tasks), solved_fraction=solved / len(tasks) if tasks else None,
                controls=len(rows) - len(tasks), rejected=sum(not r["accepted"] for r in rows),
                not_run=sum(r["observed"] == "censored" for r in rows),
                unserved=sum(r["observed"] == "unserved" for r in rows),
                repairs=sum(r["repairs"] for r in rows), elapsed_ns=sum(r["elapsed_ns"] for r in rows),
                cost_usd_micros=sum(costs) if len(costs) == len(rows) else None,
                unknown_cost_rows=len(rows) - len(costs))


def compare(corpus, baseline, candidate):
    raw = blob(corpus)
    manifest = json.loads(raw, object_pairs_hook=unique)
    fields(manifest, "schema_version oracle_digest dataset_digest cases")
    require(type(manifest["schema_version"]) is int and manifest["schema_version"] == 1, "unsupported schema")
    for field in ("dataset_digest", "oracle_digest"):
        digest(manifest[field])
    cases = indexed(manifest["cases"])
    for case in cases.values():
        fields(case, "case_id mode expected")
        require(case["mode"] in ("deterministic", "replay", "live") and
                case["expected"] in ("pass", "fail", "not_run"), "invalid case plan")
    report: dict[str, object] = {"corpus_digest": sha(raw)}
    for label, path in (("baseline", baseline), ("candidate", candidate)):
        run = json.loads(blob(path), object_pairs_hook=unique)
        fields(run, "schema_version candidate oracle_digest corpus_digest rows")
        require(type(run["schema_version"]) is int and run["schema_version"] == 1, "unsupported schema")
        require(run["corpus_digest"] == report["corpus_digest"] and
                run["oracle_digest"] == manifest["oracle_digest"], "corpus or oracle mismatch")
        digest(run["candidate"])
        rows = indexed(run["rows"])
        require(rows.keys() == cases.keys(), "incomplete or foreign case set")
        evidence_dir = path.parent / "evidence"
        require(not evidence_dir.is_symlink(), "invalid evidence directory")
        by_mode = {}
        for key, row in rows.items():
            fields(row, "case_id expected mode observed accepted evidence repairs elapsed_ns cost_usd_micros")
            require(all(row[k] == cases[key][k] for k in ("mode", "expected")), "case plan mismatch")
            require(type(row["accepted"]) is bool and row["observed"] in
                    ("pass", "fail", "censored", "unserved"), "invalid verdict")
            for field in ("repairs", "elapsed_ns", "cost_usd_micros"):
                v = row[field]
                require((field == "cost_usd_micros" and v is None) or
                        (type(v) is int and 0 <= v < 2**64), "invalid measurement")
            digest(row["evidence"])
            require(sha(blob(evidence_dir / row["evidence"])) == row["evidence"], "evidence mismatch")
            by_mode.setdefault(row["mode"], []).append(row)
        report[label] = {"digest": run["candidate"], "modes": {m: summarize(rs) for m, rs in by_mode.items()}}
    return report


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit("usage: eval-metrics.py CORPUS BASELINE CANDIDATE")
    try:
        print(json.dumps(compare(*map(Path, sys.argv[1:])), sort_keys=True, indent=2))
    except Invalid as exc:
        sys.exit(str(exc))
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        sys.exit("unreadable or invalid evaluation data")
