import importlib.machinery
import importlib.util
import io
import json
import random
import sys
import tempfile
from pathlib import Path
from unittest import mock, TestCase

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import gate  # noqa: E402
import journal  # noqa: E402


def load_cli():
    loader = importlib.machinery.SourceFileLoader("jevgatecli", str(ROOT / "jev-gate"))
    spec = importlib.util.spec_from_loader("jevgatecli", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


cli = load_cli()


def strip_ansi(s):
    import re
    return re.sub(r"\033\[[0-9;]*m", "", s)


def strip_csi(s):
    """Strip every ANSI control sequence, including cursor-movement and clear-line, not just color."""
    import re
    return re.sub(r"\033\[[0-9;]*[A-Za-z]", "", s)


def visible_lines(raw):
    return [l for l in strip_csi(raw).replace("\r", "").splitlines() if l != ""]


class AnimateLogo(TestCase):
    def test_disabled_prints_the_static_block_letters_once(self):
        out = io.StringIO()
        with mock.patch("sys.stdout", out):
            cli.animate_logo(enabled=False, color=False)
        lines = visible_lines(out.getvalue())
        self.assertEqual(len(lines), cli._GLYPH_H)
        self.assertTrue(any("#" in l for l in lines))
        self.assertTrue(all(set(l) <= {" ", "#"} for l in lines))  # no stray stars in the static render

    def test_enabled_final_frame_matches_the_static_block_letters(self):
        dynamic = io.StringIO()
        with mock.patch("sys.stdout", dynamic), mock.patch("time.sleep"):
            cli.animate_logo(enabled=True, color=False, frames=6, delay=0, rng=random.Random(3))
        static = io.StringIO()
        with mock.patch("sys.stdout", static):
            cli.animate_logo(enabled=False, color=False)
        self.assertEqual(visible_lines(dynamic.getvalue())[-cli._GLYPH_H:], visible_lines(static.getvalue()))

    def test_stars_twinkle_before_the_final_frame(self):
        out = io.StringIO()
        with mock.patch("sys.stdout", out), mock.patch("time.sleep"):
            cli.animate_logo(enabled=True, color=False, frames=10, delay=0, rng=random.Random(7))
        lines = visible_lines(out.getvalue())
        early = "\n".join(lines[:-cli._GLYPH_H])
        self.assertTrue(any(star in early for star in cli._STARS))

    def test_color_wraps_lit_pixels_but_not_the_whole_line(self):
        out = io.StringIO()
        with mock.patch("sys.stdout", out):
            cli.animate_logo(enabled=False, color=True)
        self.assertIn("\033[1;36m", out.getvalue())


class Status(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.config_dir = Path(self.tmp.name) / "config"
        self.state_dir = Path(self.tmp.name) / "state"
        self.addCleanup(self.tmp.cleanup)
        patches = [mock.patch.object(gate, "CONFIG_DIR", self.config_dir),
                   mock.patch.object(journal, "STATE_DIR", self.state_dir),
                   mock.patch.object(cli.gate, "Config", gate.Config),
                   mock.patch.object(cli.gate, "hook_installed", lambda: False)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def run_status(self, no_color=True):
        out = io.StringIO()
        with mock.patch("sys.stdout", out):
            code = cli.cmd_status(argparse_namespace(no_color=no_color))
        return code, out.getvalue()

    def _row(self, text, label):
        return next(l for l in text.splitlines() if l.strip().startswith(label))

    def test_reports_missing_hook_and_key_as_not_ok(self):
        code, text = self.run_status()
        self.assertEqual(code, 1)
        self.assertIn("no", self._row(text, "hook"))
        self.assertIn("no", self._row(text, "api key"))

    def test_reports_installed_hook_and_present_key(self):
        with mock.patch.object(cli.gate, "hook_installed", lambda: True):
            self.config_dir.mkdir(parents=True)
            (self.config_dir / ".env").write_text("TYPESAFE_API_KEY=x\n")
            code, text = self.run_status()
        self.assertEqual(code, 0)
        self.assertIn("yes", self._row(text, "hook"))
        self.assertIn("yes", self._row(text, "api key"))

    def test_reports_log_count_and_last_command(self):
        journal.append({"decision": "allow", "command": "git status", "reason": "read-only"}, state_dir=self.state_dir)
        journal.append({"decision": "ask", "command": "curl x", "reason": "network"}, state_dir=self.state_dir)
        _, text = self.run_status()
        self.assertIn("2", text)
        self.assertIn("curl x", text)

    def test_bad_config_is_reported_not_raised(self):
        self.config_dir.mkdir(parents=True)
        (self.config_dir / "config.json").write_text('{"mode": "yolo"}')
        code, text = self.run_status()
        self.assertEqual(code, 1)
        self.assertIn("config error", text)


def argparse_namespace(**kwargs):
    class NS:
        pass
    ns = NS()
    for k, v in kwargs.items():
        setattr(ns, k, v)
    return ns


class Hotkeys(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.config_dir = Path(self.tmp.name) / "config"
        self.addCleanup(self.tmp.cleanup)

    def test_s_e_a_set_the_corresponding_mode(self):
        for key, mode in (("s", "shadow"), ("e", "explain"), ("a", "auto")):
            result = cli.handle_key(key, self.config_dir, color=False)
            self.assertIn(mode, result)
            self.assertEqual(gate.Config.load(self.config_dir).mode, mode)

    def test_q_means_quit_without_touching_mode(self):
        gate.set_mode("explain", config_dir=self.config_dir)
        self.assertEqual(cli.handle_key("q", self.config_dir, color=False), "QUIT")
        self.assertEqual(cli.handle_key("Q", self.config_dir, color=False), "QUIT")
        self.assertEqual(gate.Config.load(self.config_dir).mode, "explain")

    def test_unknown_keys_are_ignored(self):
        for key in ("x", "1", " ", "\n"):
            self.assertIsNone(cli.handle_key(key, self.config_dir, color=False))

    def test_color_wraps_the_confirmation(self):
        plain = cli.handle_key("s", self.config_dir, color=False)
        colored = cli.handle_key("s", self.config_dir, color=True)
        self.assertNotIn("\033", plain)
        self.assertIn("\033", colored)
        self.assertIn("shadow", colored)

    def test_disabled_entirely_when_stdin_is_not_a_tty(self):
        with mock.patch("sys.stdin") as stdin:
            stdin.isatty.return_value = False
            self.assertIsNone(cli.start_hotkeys(self.config_dir, color=False))


class Install(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.config_dir = Path(self.tmp.name) / "config"
        self.addCleanup(self.tmp.cleanup)
        patches = [mock.patch.object(gate, "CONFIG_DIR", self.config_dir),
                   mock.patch.object(cli, "_link_into_path", lambda: (Path("/fake/bin/jev-gate"), True, True))]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def run_install(self, no_prompt=True, stdin_tty=False, key_input="", register_result=True):
        out = io.StringIO()
        stdin = mock.Mock()
        stdin.isatty.return_value = stdin_tty
        with mock.patch("sys.stdout", out), mock.patch("sys.stdin", stdin), \
             mock.patch.object(cli.gate, "register_hook", return_value=register_result) as register, \
             mock.patch("getpass.getpass", return_value=key_input):
            code = cli.cmd_install(argparse_namespace(no_color=True, no_prompt=no_prompt))
        return code, out.getvalue(), register

    def test_fresh_install_registers_hook_and_defaults_to_shadow(self):
        code, text, register = self.run_install()
        self.assertEqual(code, 0)
        register.assert_called_once()
        self.assertIn("shadow", text)
        self.assertEqual(gate.Config.load(self.config_dir).mode, "shadow")

    def test_no_prompt_skips_asking_for_a_key(self):
        with mock.patch("getpass.getpass") as getpass_mock:
            _, text, _ = self.run_install(no_prompt=True)
            getpass_mock.assert_not_called()
        self.assertIn("add TYPESAFE_API_KEY", text)
        self.assertFalse((self.config_dir / ".env").exists())

    def test_non_tty_stdin_skips_asking_even_without_no_prompt(self):
        _, text, _ = self.run_install(no_prompt=False, stdin_tty=False)
        self.assertFalse((self.config_dir / ".env").exists())

    def test_prompts_for_key_on_a_real_tty_and_writes_it(self):
        _, text, _ = self.run_install(no_prompt=False, stdin_tty=True, key_input="sk-test-123")
        self.assertIn(str(self.config_dir / ".env"), text)
        self.assertEqual((self.config_dir / ".env").read_text().strip(), "TYPESAFE_API_KEY=sk-test-123")

    def test_blank_key_input_is_treated_like_skipping(self):
        _, text, _ = self.run_install(no_prompt=False, stdin_tty=True, key_input="   ")
        self.assertFalse((self.config_dir / ".env").exists())
        self.assertIn("add TYPESAFE_API_KEY", text)

    def test_existing_key_is_never_reprompted(self):
        self.config_dir.mkdir(parents=True)
        (self.config_dir / ".env").write_text("TYPESAFE_API_KEY=already-here\n")
        with mock.patch("getpass.getpass") as getpass_mock:
            self.run_install(no_prompt=False, stdin_tty=True)
            getpass_mock.assert_not_called()

    def test_existing_config_mode_is_not_overwritten(self):
        gate.set_mode("explain", config_dir=self.config_dir)
        self.run_install()
        self.assertEqual(gate.Config.load(self.config_dir).mode, "explain")

    def test_already_registered_hook_is_reported_not_re_added(self):
        _, text, register = self.run_install(register_result=False)
        register.assert_called_once()
        self.assertIn("already registered", text)


class Uninstall(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.config_dir = Path(self.tmp.name) / "config"
        self.state_dir = Path(self.tmp.name) / "state"
        self.addCleanup(self.tmp.cleanup)
        patches = [mock.patch.object(gate, "CONFIG_DIR", self.config_dir),
                   mock.patch.object(journal, "STATE_DIR", self.state_dir)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def run_uninstall(self, unregister_result=True, unlink_result=(Path("/fake/bin/jev-gate"), True)):
        out = io.StringIO()
        with mock.patch("sys.stdout", out), \
             mock.patch.object(cli.gate, "unregister_hook", return_value=unregister_result), \
             mock.patch.object(cli, "_unlink_from_path", return_value=unlink_result):
            code = cli.cmd_uninstall(argparse_namespace(no_color=True))
        return code, out.getvalue()

    def test_reports_hook_removed_and_symlink_removed(self):
        code, text = self.run_uninstall()
        self.assertEqual(code, 0)
        self.assertIn("removed the PreToolUse hook", text)
        self.assertIn("removed", text)

    def test_reports_hook_was_not_registered(self):
        _, text = self.run_uninstall(unregister_result=False)
        self.assertIn("wasn't registered", text)

    def test_reports_no_symlink_to_remove(self):
        _, text = self.run_uninstall(unlink_result=(Path("/fake/bin/jev-gate"), False))
        self.assertIn("no symlink", text)

    def test_mentions_what_is_left_behind_for_a_reinstall(self):
        _, text = self.run_uninstall()
        self.assertIn(str(self.config_dir), text)
        self.assertIn(str(self.state_dir), text)


class Mode(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.config_dir = Path(self.tmp.name) / "config"
        self.addCleanup(self.tmp.cleanup)
        patch = mock.patch.object(gate, "CONFIG_DIR", self.config_dir)
        patch.start()
        self.addCleanup(patch.stop)

    def run_mode(self, value=None, no_color=True):
        out = io.StringIO()
        with mock.patch("sys.stdout", out):
            code = cli.cmd_mode(argparse_namespace(value=value, no_color=no_color))
        return code, out.getvalue()

    def test_no_value_shows_the_current_mode(self):
        gate.set_mode("explain", config_dir=self.config_dir)
        code, text = self.run_mode(value=None)
        self.assertEqual(code, 0)
        self.assertIn("explain", text)

    def test_setting_a_value_persists_it(self):
        code, text = self.run_mode(value="auto")
        self.assertEqual(code, 0)
        self.assertIn("auto", text)
        self.assertEqual(gate.Config.load(self.config_dir).mode, "auto")

    def test_setting_auto_prints_a_heads_up(self):
        _, text = self.run_mode(value="auto")
        self.assertIn("auto-approving", text)

    def test_setting_shadow_has_no_heads_up(self):
        _, text = self.run_mode(value="shadow")
        self.assertNotIn("heads up", text)

    def test_no_value_with_a_broken_config_reports_the_error_not_a_crash(self):
        self.config_dir.mkdir(parents=True)
        (self.config_dir / "config.json").write_text('{"mode": "yolo"}')
        code, text = self.run_mode(value=None)
        self.assertEqual(code, 1)
        self.assertIn("couldn't read config", text)


class Parser(TestCase):
    def test_no_args_default_to_watch(self):
        args = cli.build_parser().parse_args(["watch"])  # main() itself injects this default; check wiring
        self.assertEqual(args.func, cli.cmd_watch)

    def test_status_subcommand_parses(self):
        args = cli.build_parser().parse_args(["status"])
        self.assertEqual(args.func, cli.cmd_status)

    def test_mode_subcommand_parses_with_and_without_a_value(self):
        args = cli.build_parser().parse_args(["mode"])
        self.assertEqual((args.func, args.value), (cli.cmd_mode, None))
        args = cli.build_parser().parse_args(["mode", "auto"])
        self.assertEqual(args.value, "auto")

    def test_mode_rejects_an_unknown_value(self):
        with self.assertRaises(SystemExit), mock.patch("sys.stderr", io.StringIO()):
            cli.build_parser().parse_args(["mode", "yolo"])

    def test_install_and_uninstall_subcommands_parse(self):
        args = cli.build_parser().parse_args(["install"])
        self.assertEqual((args.func, args.no_prompt), (cli.cmd_install, False))
        args = cli.build_parser().parse_args(["install", "--no-prompt"])
        self.assertTrue(args.no_prompt)
        args = cli.build_parser().parse_args(["uninstall"])
        self.assertEqual(args.func, cli.cmd_uninstall)

    def test_main_with_no_argv_runs_watch(self):
        with mock.patch.object(cli, "cmd_watch", return_value=0) as watch:
            code = cli.main([])
        self.assertEqual(code, 0)
        watch.assert_called_once()


if __name__ == "__main__":
    import unittest
    unittest.main()
