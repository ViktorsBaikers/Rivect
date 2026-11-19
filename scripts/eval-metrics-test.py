import json
import shutil
import subprocess
import sys
import tempfile
import runpy
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("eval-metrics.py")
FIXTURE = SCRIPT.resolve().parents[1] / "tests/fixtures/eval-metrics"
metrics = runpy.run_path(str(SCRIPT))


class MetricsTest(unittest.TestCase):
    def test_negative_control_is_not_a_solution(self):
        rows = [dict(accepted=True, expected="fail", observed="fail", repairs=0,
                     elapsed_ns=1, cost_usd_micros=None)]
        self.assertEqual(metrics["summarize"](rows)["solved"], 0)

    def test_unserved_and_censored_remain_in_denominator(self):
        rows = [dict(expected="pass", observed=outcome, accepted=outcome == "pass",
                     elapsed_ns=7, repairs=1, cost_usd_micros=0)
                for outcome in ("pass", "censored", "unserved")]
        report = metrics["summarize"](rows)
        self.assertEqual((report["tasks"], report["solved"], report["not_run"], report["unserved"]),
                         (3, 1, 1, 1))
        self.assertEqual((report["repairs"], report["cost_usd_micros"]), (3, 0))

    def test_measured_fixture(self):
        report = metrics["compare"](*(FIXTURE / f for f in ("corpus.json", "baseline.json", "candidate.json")))
        base, new = [report[k]["modes"]["deterministic"] for k in ("baseline", "candidate")]
        self.assertEqual((base["solved_fraction"], new["solved_fraction"]), (0.5, 1.0))
        self.assertEqual((base["repairs"], base["elapsed_ns"]), (0, 6037000))
        self.assertIsNone(new["cost_usd_micros"])

    def test_refuses_uncomparable_or_sensitive_input_without_echo(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copytree(FIXTURE / "evidence", root / "evidence")
            for mutate in (lambda d: d["rows"].pop(), lambda d: d["rows"].append(d["rows"][0]),
                           lambda d: d.update(corpus_digest="0" * 64),
                           lambda d: d.update(oracle_digest="0" * 64),
                           lambda d: d["rows"][0].update(mode="live"),
                           lambda d: d["rows"][0].update(prompt="PRIVATE"),
                           lambda d: d["rows"][0].update(evidence="../PRIVATE"),
                           lambda d: d["rows"][0].update(evidence="f" * 64),
                           lambda d: d["rows"][0].update(repairs=True)):
                data = json.loads((FIXTURE / "baseline.json").read_bytes())
                mutate(data)
                (root / "run.json").write_text(json.dumps(data))
                p = subprocess.run([sys.executable, SCRIPT, FIXTURE / "corpus.json", root / "run.json",
                                    FIXTURE / "candidate.json"], capture_output=True)
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(p.stdout, b"")
                self.assertNotIn(b"PRIVATE", p.stderr)


if __name__ == "__main__":
    unittest.main()
