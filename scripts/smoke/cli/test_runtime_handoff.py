"""Portable controls for the delayed typed-init shutdown oracle; no VM is started."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import sys


sys.path.insert(0, os.environ["MSB_HANDOFF_SUPPORT"])
from smoke_contract import validate_stop

spec = importlib.util.spec_from_file_location("handoff", Path(__file__).with_name("runtime-handoff.py"))
handoff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(handoff)


class HandoffContract(unittest.TestCase):
    def stop(self):
        return {"cli_status": 0, "elapsed": 3.2,
                "runtime_exit": {"code": os.CLD_EXITED, "status": 0},
                "flush_marker": True, "signals": [],
                "logs": "core.shutdown forwarded to agentd\n"}

    def report(self):
        return {"status": "passed", "typed_init": True, "activation": True,
                "delayed_flush": True, "stops": [self.stop()], "cancelled": [],
                "cleanup": {"empty_store": True, "children_empty": True,
                            "forced": False, "errors": []}}

    def test_delayed_normal_exit(self):
        handoff.validate_delayed_stop(self.stop(), validate_stop)

    def test_old_two_second_window_fails(self):
        stop = self.stop()
        stop["elapsed"] = 2.0
        with self.assertRaisesRegex(RuntimeError, "delayed guest flush"):
            handoff.validate_delayed_stop(stop, validate_stop)

    def test_eight_second_boundary_fails(self):
        stop = self.stop()
        stop["elapsed"] = 8.0
        with self.assertRaises(ValueError):
            handoff.validate_delayed_stop(stop, validate_stop)

    def test_marker_is_mandatory(self):
        stop = self.stop()
        stop["flush_marker"] = False
        with self.assertRaises(ValueError):
            handoff.validate_delayed_stop(stop, validate_stop)

    def test_fallback_is_not_clean_shutdown(self):
        stop = self.stop()
        stop["logs"] += "flush window elapsed, triggering host exit"
        with self.assertRaises(ValueError):
            handoff.validate_delayed_stop(stop, validate_stop)

    def test_exact_exit_and_no_forced_signal_required(self):
        for key, value in (("runtime_exit", {"code": os.CLD_KILLED, "status": 9}),
                           ("runtime_exit", {"code": os.CLD_EXITED, "status": 1}),
                           ("signals", [{"signal": 15}])):
            with self.subTest(key=key, value=value):
                stop = self.stop()
                stop[key] = value
                with self.assertRaises(ValueError):
                    handoff.validate_delayed_stop(stop, validate_stop)

    def test_shutdown_forwarding_required(self):
        stop = self.stop()
        stop["logs"] = ""
        with self.assertRaisesRegex(RuntimeError, "forwarding"):
            handoff.validate_delayed_stop(stop, validate_stop)

    def test_flush_is_after_delay_and_sync(self):
        script = handoff.flush_script({"coreutils": "/nix/store/utils"}, "fixed-marker")
        self.assertLess(script.index("/bin/sleep 3\n"), script.index("> /var/lib/msb-handoff-flush"))
        self.assertLess(script.index("/bin/sync -f"), script.index("> /dev/console"))
        self.assertEqual(script.count("fixed-marker"), 2)

    def test_validated_stop_removed_before_clearing_cleanup_ownership(self):
        fixture = mock.Mock(name="fixture")
        fixture.name, fixture.attempted = "owned-sandbox", True
        fixture.report = {"stops": [self.stop()]}

        def removed(argv, timeout):
            self.assertTrue(fixture.attempted)
            self.assertNotIn("delayed_flush", fixture.report)
            self.assertEqual(argv, ["remove", "owned-sandbox"])
            self.assertEqual(timeout, 10)

        fixture.command.side_effect = removed
        handoff.retire_stopped_fixture(fixture, validate_stop)
        fixture.command.assert_called_once()
        self.assertFalse(fixture.attempted)
        self.assertTrue(fixture.report["delayed_flush"])

    def test_invalid_stop_retains_cleanup_ownership_without_removal(self):
        fixture = mock.Mock()
        fixture.attempted = True
        stop = self.stop()
        stop["runtime_exit"]["status"] = 1
        fixture.report = {"stops": [stop]}
        with self.assertRaises(ValueError):
            handoff.retire_stopped_fixture(fixture, validate_stop)
        self.assertTrue(fixture.attempted)
        self.assertNotIn("delayed_flush", fixture.report)
        fixture.command.assert_not_called()

    def test_failed_or_interrupted_remove_retains_cleanup_ownership(self):
        for error in (RuntimeError("remove failed"), InterruptedError("cancelled")):
            fixture = mock.Mock()
            fixture.attempted = True
            fixture.report = {"stops": [self.stop()]}
            fixture.command.side_effect = error
            with self.subTest(error=error), self.assertRaises(type(error)):
                handoff.retire_stopped_fixture(fixture, validate_stop)
            self.assertTrue(fixture.attempted)
            self.assertNotIn("delayed_flush", fixture.report)

    def test_only_complete_result_passes(self):
        report = self.report()
        handoff.validate_result(report)
        for key in ("typed_init", "activation", "delayed_flush"):
            broken = copy.deepcopy(report)
            broken[key] = False
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                handoff.validate_result(broken)

    def test_cleanup_or_cancellation_cannot_pass(self):
        for change in ({"forced": True}, {"children_empty": False}, {"errors": ["stop failed"]}):
            report = self.report()
            report["cleanup"].update(change)
            with self.assertRaises(RuntimeError):
                handoff.validate_result(report)
        report = self.report()
        report["cancelled"] = [15]
        with self.assertRaises(RuntimeError):
            handoff.validate_result(report)

    def test_cancel_during_first_dump_rewrites_receipt(self):
        report = self.report()
        original = json.dump
        calls = []

        def dumping(*args, **kwargs):
            original(*args, **kwargs)
            calls.append(True)
            if len(calls) == 1:
                report["cancelled"].append(15)

        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "result.json"
            with mock.patch.object(handoff.json, "dump", side_effect=dumping):
                handoff.write_receipt(path, report, report["cancelled"])
            actual = json.loads(path.read_text())
            self.assertEqual(actual["status"], "failed")
            self.assertEqual(actual["cancelled"], [15])
            self.assertEqual(len(calls), 2)

    def test_cancel_during_first_fsync_preserves_primary(self):
        report = self.report()
        report["status"], report["error"] = "failed", "original stop failure"
        calls = []

        def synced(_fd):
            calls.append(True)
            if len(calls) == 1:
                report["cancelled"].append(2)

        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "result.json"
            with mock.patch.object(handoff.os, "fsync", side_effect=synced):
                handoff.write_receipt(path, report, report["cancelled"])
            actual = json.loads(path.read_text())
            self.assertEqual(actual["status"], "failed")
            self.assertEqual(actual["error"], "original stop failure")
            self.assertEqual(actual["cancelled"], [2])
            self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
