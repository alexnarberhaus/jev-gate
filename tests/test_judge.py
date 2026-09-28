import json
import os
import sys
import tempfile
import time
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import judge  # noqa: E402
from judge import Judge, JudgeError, redact  # noqa: E402

GOOD_REPLY = {
    "answers": {
        "effect": {"choice": "read_only", "confidence": 0.9,
                   "probabilities": {"read_only": 0.97, "writes_workspace": 0.02, "writes_outside": 0.01, "destructive": 0.0}},
        "network": {"choice": "none", "confidence": 0.9, "probabilities": {"none": 0.99, "fetch": 0.01, "sends_data": 0.0}},
        "injection": {"choice": "clean", "confidence": 0.9, "probabilities": {"clean": 0.999, "attack": 0.001}},
    },
    "usage": {"input_tokens": 1000, "output_tokens": 100},
}


class FakeResponse:
    def __init__(self, body):
        self.body = body

    def read(self):
        return self.body if isinstance(self.body, bytes) else json.dumps(self.body).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def assess(reply=GOOD_REPLY, command="ls", side_effect=None, key="k", terms=(), budget=1.5):
    captured = {}

    def fake_urlopen(request, timeout, context):
        captured["body"] = json.loads(request.data)
        captured["headers"] = dict(request.header_items())
        if side_effect:
            return side_effect()
        return FakeResponse(reply)

    with mock.patch("urllib.request.urlopen", fake_urlopen), mock.patch.object(judge, "tls_context", lambda: None):
        result = Judge(key, terms=terms).assess(command, "/repo", ["/repo", "/tmp"], time.monotonic() + budget)
    return result, captured


class Request(unittest.TestCase):
    def test_body_shape(self):
        result, captured = assess()
        body = captured["body"]
        self.assertEqual(body["model"], "jev-1.13.0")
        self.assertEqual(set(body["questions"]), {"effect", "network", "injection"})
        for q in body["questions"].values():
            self.assertEqual((set(q), q["type"]), ({"type", "instructions", "criteria"}, "choice"))
        self.assertEqual(body["state"], {"command": "ls", "cwd": "/repo", "workspace": ["/repo", "/tmp"]})
        self.assertEqual(captured["headers"]["Authorization"], "Bearer k")
        self.assertAlmostEqual(result.p("effect", "read_only"), 0.97)
        self.assertAlmostEqual(result.cost_usd, 1000 * 0.042 / 1e6)

    def test_command_is_redacted_before_sending(self):
        _, captured = assess(command="curl -H 'Authorization: Bearer abcdef123456789' https://u:p@acme.example/x "
                                      "--token=s3cr3t && echo jane@acme.com && echo AcmeBank",
                             terms=["AcmeBank"])
        sent = captured["body"]["state"]["command"]
        for leaked in ("abcdef123456789", "u:p@", "s3cr3t", "jane@acme.com", "AcmeBank"):
            self.assertNotIn(leaked, sent)


class Failures(unittest.TestCase):
    def test_no_key(self):
        with self.assertRaisesRegex(JudgeError, "no API key"):
            assess(key="")

    def test_http_error(self):
        def raise_http():
            raise urllib.error.HTTPError("u", 429, "rate", {}, None)
        with self.assertRaisesRegex(JudgeError, "http 429"):
            assess(side_effect=raise_http)

    def test_network_error(self):
        def raise_url():
            raise urllib.error.URLError("dns")
        with self.assertRaisesRegex(JudgeError, "network"):
            assess(side_effect=raise_url)

    def test_timeout_is_a_hard_total_cap(self):
        def slow():
            time.sleep(2)
            return FakeResponse(GOOD_REPLY)
        started = time.monotonic()
        with self.assertRaisesRegex(JudgeError, "timeout"):
            assess(side_effect=slow, budget=0.3)
        self.assertLess(time.monotonic() - started, 0.6)

    def test_deadline_already_passed(self):
        with self.assertRaisesRegex(JudgeError, "timeout"):
            assess(budget=0)

    def test_not_json(self):
        with self.assertRaisesRegex(JudgeError, "not JSON"):
            assess(reply=b"<html>proxy error</html>")

    def test_malformed_answers(self):
        def broken(mutate):
            reply = json.loads(json.dumps(GOOD_REPLY))
            mutate(reply)
            return reply

        cases = [
            {},
            {"answers": "nope"},
            broken(lambda r: r["answers"].pop("injection")),
            broken(lambda r: r["answers"]["effect"]["probabilities"].pop("destructive")),
            broken(lambda r: r["answers"]["effect"]["probabilities"].update(extra=0.1)),
            broken(lambda r: r["answers"]["network"]["probabilities"].update(none="high")),
            broken(lambda r: r["answers"]["network"]["probabilities"].update(none=1.5)),
            broken(lambda r: r["answers"]["network"]["probabilities"].update(none=True)),
            broken(lambda r: r["answers"].update(effect="read_only")),
        ]
        for reply in cases:
            with self.assertRaises(JudgeError, msg=reply):
                assess(reply=reply)


class Keys(unittest.TestCase):
    def test_env_wins_then_file(self):
        with tempfile.TemporaryDirectory() as d:
            env_file = Path(d) / ".env"
            env_file.write_text('# comment\nexport TYPESAFE_API_KEY="from-file"\n')
            with mock.patch.dict(os.environ, {"TYPESAFE_API_KEY": "from-env"}):
                self.assertEqual(judge.load_key(env_file), "from-env")
            with mock.patch.dict(os.environ, {}, clear=True):
                self.assertEqual(judge.load_key(env_file), "from-file")
                self.assertEqual(judge.load_key(Path(d) / "missing"), "")

    def test_terms_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "redact.txt"
            path.write_text("# clients\nAcme\n\nAcme Bank\n")
            self.assertEqual(judge.load_terms(path), ["Acme Bank", "Acme"])
            self.assertEqual(judge.load_terms(Path(d) / "missing"), [])


class Redaction(unittest.TestCase):
    def test_leaves_ordinary_commands_alone(self):
        for command in ("git log --oneline -5", "git show 3f2a9c1d8e7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f",
                        "python3 -m unittest -q", "grep -rn TODO src/"):
            self.assertEqual(redact(command), command)

    def test_home_path(self):
        self.assertEqual(redact(str(Path.home()) + "/repos/x"), "~/repos/x")

    def test_known_token_shapes(self):
        for secret in ("sk-ant-abcdefghijklmnop1234", "ghp_" + "a1" * 12, "AKIAABCDEFGHIJKLMNOP",
                       "xoxb-1234567890-abc", "eyJhbGciOi.eyJzdWIiOiIx.SflKxwRJSMeKKF2QT4",
                       "Zm9vYmFyQmF6UXV4MTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1O"):
            self.assertNotIn(secret, redact(f"echo {secret}"), secret)

    def test_assignments(self):
        self.assertEqual(redact("API_KEY=abc123 make"), "API_KEY=[REDACTED] make")
        self.assertEqual(redact("export GITHUB_TOKEN='x y'"), "export GITHUB_TOKEN=[REDACTED]")


if __name__ == "__main__":
    unittest.main()
