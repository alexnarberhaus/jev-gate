import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import journal  # noqa: E402


def entry(**overrides):
    base = {"ts": "2026-09-28T12:00:00.000+00:00", "decision": "allow", "command": "git status",
            "reason": "read-only (read-only 1.00)", "latency_ms": 637.2, "cost_usd": 3.76e-05, "observed": True}
    base.update(overrides)
    return base


class Append(unittest.TestCase):
    def test_writes_one_line_with_a_timestamp(self):
        with tempfile.TemporaryDirectory() as d:
            journal.append({"decision": "allow"}, state_dir=d)
            lines = journal.path(d).read_text().splitlines()
            self.assertEqual(len(lines), 1)
            self.assertIn("ts", json.loads(lines[0]))


class TailLines(unittest.TestCase):
    def test_missing_file_is_empty(self):
        self.assertEqual(journal.tail_lines(Path("/nonexistent/decisions.jsonl"), 5), [])

    def test_keeps_only_the_last_n_and_skips_blanks(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "decisions.jsonl"
            p.write_text("\n".join(f'{{"i": {i}}}' for i in range(10)) + "\n\n")
            lines = journal.tail_lines(p, 3)
            self.assertEqual([json.loads(l)["i"] for l in lines], [7, 8, 9])


class Follow(unittest.TestCase):
    def test_yields_lines_appended_after_it_starts(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "decisions.jsonl"
            p.write_text('{"i": "before"}\n')  # written before follow() starts: must NOT be yielded
            seen = []
            gen = journal.follow(p, poll_s=0.02)

            def append_soon():
                time.sleep(0.05)
                with p.open("a") as f:
                    f.write('{"i": "after"}\n')

            threading.Thread(target=append_soon).start()
            seen.append(next(gen))
            self.assertEqual(json.loads(seen[0])["i"], "after")

    def test_recovers_when_the_file_is_truncated(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "decisions.jsonl"
            p.write_text('{"i": 1}\n{"i": 2}\n')
            gen = journal.follow(p, poll_s=0.02)

            def truncate_and_write():
                time.sleep(0.05)
                p.write_text('{"i": "new"}\n')

            threading.Thread(target=truncate_and_write).start()
            self.assertEqual(json.loads(next(gen))["i"], "new")

    def test_waits_for_a_file_that_does_not_exist_yet(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "decisions.jsonl"
            gen = journal.follow(p, poll_s=0.02)

            def create_soon():
                time.sleep(0.05)
                p.write_text('{"i": "created"}\n')

            threading.Thread(target=create_soon).start()
            self.assertEqual(json.loads(next(gen))["i"], "created")


class FormatEntry(unittest.TestCase):
    def test_plain_allow_and_ask(self):
        allow = journal.format_entry(entry(), color=False)
        self.assertIn("12:00:00", allow)
        self.assertIn("ALLOW", allow)
        self.assertIn("git status", allow)
        self.assertIn("637 ms", allow)
        self.assertIn("$0.000038", allow)
        self.assertIn("background", allow)

        ask = journal.format_entry(entry(decision="ask", reason="deny-list: recursive delete", latency_ms=None,
                                          cost_usd=None, observed=False), color=False)
        self.assertIn("ASK", ask)
        self.assertNotIn("background", ask)
        self.assertNotIn("ms", ask.split("·")[0])  # no latency printed when there was no Jev call

    def test_unknown_decision_does_not_crash(self):
        out = journal.format_entry(entry(decision="whatever"), color=False)
        self.assertIn("WHATEVER", out)

    def test_color_adds_escape_codes_plain_does_not(self):
        self.assertNotIn("\033", journal.format_entry(entry(), color=False))
        self.assertIn("\033", journal.format_entry(entry(), color=True))

    def test_long_commands_are_truncated(self):
        out = journal.format_entry(entry(command="x" * 300), color=False, width=100)
        self.assertIn("…", out)
        self.assertLessEqual(len(out.splitlines()[0]), 160)

    def test_timestamp_is_right_aligned_to_width(self):
        out = journal.format_entry(entry(), color=False, width=60)
        head = out.splitlines()[0]
        self.assertTrue(head.endswith("12:00:00"))
        self.assertEqual(len(head), 59)  # width - 1: one space of breathing room before the ts

    def test_reason_and_meta_share_one_detail_line(self):
        out = journal.format_entry(entry(), color=False, width=100)
        lines = out.splitlines()
        self.assertEqual(len(lines), 2)  # head + one detail line
        self.assertIn("read-only (read-only 1.00)", lines[1])
        self.assertIn("637 ms", lines[1])

    def test_meta_is_colored_separately_from_the_reason(self):
        out = journal.format_entry(entry(), color=True, width=100)
        self.assertIn(f"{journal._DIM}read-only (read-only 1.00){journal._RESET}", out)
        self.assertIn(f"{journal._META}637 ms{journal._RESET}", out)

    def test_no_detail_line_when_nothing_to_show(self):
        out = journal.format_entry(entry(reason="", latency_ms=None, cost_usd=None, observed=False), color=False)
        self.assertEqual(len(out.splitlines()), 1)

    def test_missing_fields_render_without_crashing(self):
        journal.format_entry({}, color=False)


class Main(unittest.TestCase):
    def test_no_follow_prints_recent_entries_and_returns(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "decisions.jsonl"
            p.write_text(json.dumps(entry()) + "\n" + "not json\n" + json.dumps(entry(command="ls")) + "\n")
            import io
            from unittest import mock
            out = io.StringIO()
            with mock.patch.object(journal, "STATE_DIR", d), mock.patch("sys.stdout", out):
                code = journal.main(["--no-follow", "--no-color"])
            self.assertEqual(code, 0)
            self.assertIn("git status", out.getvalue())
            self.assertIn("ls", out.getvalue())  # the malformed line in between is skipped, not fatal


class Watch(unittest.TestCase):
    def test_on_start_runs_before_any_backlog_is_printed(self):
        import io
        from unittest import mock
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "decisions.jsonl"
            p.write_text(json.dumps(entry(command="old one")) + "\n")
            out = io.StringIO()
            with mock.patch("sys.stdout", out), mock.patch.object(journal, "follow", lambda t: iter([])):
                journal.watch(n=5, follow_after=True, color=False, target=p,
                              on_start=lambda: print("BANNER-MARK"))
            text = out.getvalue()
            self.assertLess(text.index("BANNER-MARK"), text.index("old one"))

    def test_no_follow_never_calls_on_start(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "decisions.jsonl"
            p.write_text(json.dumps(entry()) + "\n")
            banner = mock.Mock()
            with mock.patch("builtins.print"):
                journal.watch(n=5, follow_after=False, color=False, target=p, on_start=banner)
            banner.assert_not_called()

    def test_default_n_zero_shows_nothing_before_following(self):
        import io
        from unittest import mock
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "decisions.jsonl"
            p.write_text(json.dumps(entry(command="should not appear")) + "\n")
            out = io.StringIO()
            with mock.patch("sys.stdout", out), mock.patch.object(journal, "follow", lambda t: iter([])):
                journal.watch(n=0, follow_after=True, color=False, target=p)
            self.assertNotIn("should not appear", out.getvalue())


if __name__ == "__main__":
    unittest.main()
