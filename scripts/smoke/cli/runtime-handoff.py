#!/usr/bin/env python3
"""Observe a delayed systemd flush through the packaged typed-init shutdown path."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import sys
import time


FLUSH_SECONDS = 3
WORK_SECONDS = 300


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def flush_script(spec, marker):
    c = spec["coreutils"] + "/bin/"
    return ("set -eu\n"
            f"{c}sleep {FLUSH_SECONDS}\n"
            f"printf '%s\\n' {shlex.quote(marker)} > /var/lib/msb-handoff-flush\n"
            f"{c}sync -f /var/lib/msb-handoff-flush\n"
            f"printf '%s\\n' {shlex.quote(marker)} > /dev/console\n")


def validate_delayed_stop(record, validate_stop):
    # The shared predicate requires exact child exit, console marker and no
    # fallback. The lower bound also rejects the historical two-second path.
    validate_stop(record)
    require(record["elapsed"] >= FLUSH_SECONDS, "delayed guest flush was not observed")
    require("core.shutdown forwarded to agentd" in record.get("logs", ""),
            "host shutdown forwarding was not observed")


def retire_stopped_fixture(fixture, validate_stop):
    validate_delayed_stop(fixture.report["stops"][0], validate_stop)
    # The selected VMM has already exited normally. Remove its stopped record
    # before inherited cleanup, which otherwise requests another stop.
    fixture.command(["remove", fixture.name], timeout=10)
    fixture.attempted = False
    fixture.report["delayed_flush"] = True


def validate_result(report):
    require(not report.get("error"), "primary runtime failure")
    require(report.get("typed_init") is True and report.get("activation") is True,
            "typed systemd activation was not established")
    require(report.get("delayed_flush") is True and len(report.get("stops", [])) == 1,
            "delayed shutdown was not established")
    require(report.get("cleanup") == {
        "empty_store": True, "children_empty": True, "forced": False, "errors": [],
    }, "owned cleanup did not complete normally")
    require(not report.get("cancelled"), "runtime test was interrupted")


def write_receipt(path, report, cancelled):
    with path.open("x") as output:
        json.dump(report, output, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
        if cancelled:
            report["status"] = "failed"
            output.seek(0)
            output.truncate()
            json.dump(report, output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())


def fixture_type(support):
    # Keep the pinned tooling tree's sibling support directory intact. No
    # process supervision or shared fixture behavior is copied or replaced.
    sys.path.insert(0, str(support))
    import msb_smoke
    import smoke_contract
    import smoke_full

    class HandoffFixture(msb_smoke.Fixture):
        def __init__(self, args, cancelled, started):
            self.cancelled = cancelled
            super().__init__(args)
            self.started = started
            self.deadline = started + WORK_SECONDS
            self.report["cancelled"] = cancelled
            self.report["limits"]["memory_floor_bytes"] = 8 * msb_smoke.GIB

        def limits(self, deadline=None):
            require(not self.cancelled, "runtime test interrupted")
            super().limits(deadline)
            require(msb_smoke.available_memory() >= 8 * msb_smoke.GIB,
                    "8 GiB available memory floor")

        def run(self):
            require("MSB_SHUTDOWN_FLUSH_TIMEOUT_MS" not in self.env,
                    "shutdown override would mask the default grace")
            require(self.command(["--version"])[1].strip() == "msb " + self.args.expected_version,
                    "wrong packaged runtime version")
            require(json.loads(self.command(["list", "--format", "json"])[1]) == [],
                    "disposable runtime state is not empty")
            self.report["import_tar"] = msb_smoke.unpack_archive(
                Path(self.spec["archive"]), self.root / "image.tar", self.limits)
            self.command(["image", "load", "--input", str(self.root / "image.tar"),
                          "--tag", self.image], timeout=180)
            self.attempted = True
            self.command(["create", self.image, "--name", self.name, "--pull", "never",
                          "--init", "/init", "--init-env", "container=microsandbox",
                          "--workdir", "/", "--security", "default", "--no-net",
                          "--cpus", "1", "--memory", "2G", "--root-disk", "4G",
                          "--max-duration", "5m", "--log-level", "debug"], timeout=60)
            record = json.loads(self.command(["inspect", self.name, "--format", "json"])[1])
            require(record.get("pending_changes") == [], "pending launch configuration")
            for key in ("config", "active_config"):
                require(record[key]["init"] == {
                    "cmd": "/init", "args": [], "env": [["container", "microsandbox"]],
                }, "typed init configuration differs")
            self.report["typed_init"] = True
            self.report["inspect"] = record
            c, systemd = self.spec["coreutils"] + "/bin/", self.spec["systemd"]
            probe = (f"test \"$({c}readlink -f /proc/1/exe)\" = "
                     f"{shlex.quote(systemd + '/lib/systemd/systemd')}\n"
                     f"{systemd}/bin/systemctl is-active --quiet guest-store-ready.target\n")
            deadline = min(self.deadline, time.monotonic() + 45)
            observations = []
            # Only this fixed read-only activation probe is retried. Agent
            # readiness can precede NixOS activation and account creation.
            while True:
                self.limits(deadline)
                status, stdout, stderr = self.execute(probe, timeout=5, check=False)
                observations[:] = [*observations[:1], {
                    "status": status, "stdout": stdout[-2048:], "stderr": stderr[-2048:],
                }]
                self.report["activation_observations"] = observations
                if status == 0:
                    break
                self.limits(deadline)
                time.sleep(0.1)
            self.report["activation"] = True
            marker = "MSB_HANDOFF_FLUSH:" + self.nonce
            path = "/tmp/" + self.nonce + "-flush.sh"
            self.execute(f"{c}cat > {path} <<'MSB_HANDOFF_SCRIPT'\n"
                         + flush_script(self.spec, marker) + "MSB_HANDOFF_SCRIPT\n"
                         + f"{systemd}/bin/systemd-run --unit={self.nonce}-flush "
                         "--property=Type=oneshot --property=RemainAfterExit=yes "
                         "--property=TimeoutStopSec=6 "
                         f"--property=ExecStop='{self.spec['bash']}/bin/bash {path}' {c}true\n"
                         f"{systemd}/bin/systemctl is-active --quiet {self.nonce}-flush.service\n")
            require(marker not in smoke_full.log_text(self.capture_logs(), source="system").splitlines(),
                    "flush marker existed before stopping")
            smoke_full.stop(self, marker)
            retire_stopped_fixture(self, smoke_contract.validate_stop)

    return HandoffFixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", required=True)
    parser.add_argument("--support", type=Path, required=True)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--msb", type=Path, required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--runtime-revision", required=True)
    parser.add_argument("--scratch", type=Path, default=Path("/tmp"))
    args = parser.parse_args()
    started, cancelled = time.monotonic(), []

    def interrupted(number, _frame):
        cancelled.append(number)

    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, interrupted)
    args.mode = "typed-handoff"
    msb = args.msb.resolve(strict=True)
    archive = Path(json.loads(args.spec.read_text())["archive"])
    for name, path in (("msb", msb), ("agentd", msb.parent.parent / "libexec/agentd"),
                       ("archive", archive)):
        with path.open("rb") as source:
            value = hashlib.file_digest(source, "sha256").hexdigest()
        setattr(args, name + "_sha256", value)
    require(time.monotonic() - started < 15 and not cancelled, "preparation exceeded its budget")
    fixture = fixture_type(args.support)(args, cancelled, started)
    print("Runtime handoff artifacts: " + str(fixture.root), flush=True)
    try:
        fixture.run()
    except BaseException as error:
        fixture.report["error"] = repr(error)
    finally:
        try:
            fixture.cleanup()
        except BaseException as error:
            fixture.report.setdefault("error", "cleanup failure: " + repr(error))
        try:
            validate_result(fixture.report)
            require(time.monotonic() - started < 390, "total runtime test deadline")
            fixture.report["status"] = "passed"
        except BaseException as error:
            fixture.report["status"] = "failed"
            fixture.report.setdefault("error", repr(error))
        fixture.report["elapsed_seconds"] = time.monotonic() - started
        write_receipt(fixture.root / "handoff-result.json", fixture.report, cancelled)
    print(json.dumps({"status": fixture.report["status"], "root": str(fixture.root)}))
    return int(fixture.report["status"] != "passed" or bool(cancelled))


if __name__ == "__main__":
    raise SystemExit(main())
