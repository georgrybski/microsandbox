#!/usr/bin/env python3
"""Exercise a packaged runtime and firmware in a disposable local microVM."""

import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--msb", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--kernel-release", type=Path, required=True)
    parser.add_argument("--scratch-parent", type=Path, default=Path("/tmp"))
    args = parser.parse_args()
    require(
        os.access("/dev/kvm", os.R_OK | os.W_OK), "read/write KVM access is required"
    )
    require(
        args.msb.is_absolute() and os.access(args.msb, os.X_OK),
        "--msb must be an executable absolute path",
    )
    require(
        args.image.is_absolute() and args.image.is_file(),
        "--image must be an absolute archive path",
    )
    expected_kernel = args.kernel_release.read_text().strip()
    require(bool(expected_kernel), "empty firmware kernel release")

    # Never reuse ambient MSB_HOME, registry credentials, context or configuration.
    root = Path(tempfile.mkdtemp(prefix="msb-runtime-smoke-", dir=args.scratch_parent))
    home = root / "home"
    home.mkdir()
    env = {
        "PATH": os.defpath,
        "HOME": str(home),
        "MSB_HOME": str(root / "msb"),
        "XDG_CONFIG_HOME": str(home / "config"),
        "XDG_CACHE_HOME": str(home / "cache"),
        "XDG_DATA_HOME": str(home / "data"),
        "XDG_STATE_HOME": str(home / "state"),
        "XDG_RUNTIME_DIR": str(home / "run"),
        "TERM": "dumb",
        "NO_COLOR": "1",
    }
    Path(env["XDG_RUNTIME_DIR"]).mkdir(mode=0o700)
    name = "runtime-smoke"
    commands = []
    started = False
    succeeded = False
    print(f"Runtime smoke artifacts: {root}", flush=True)

    def run(*arguments, timeout=90, expected=0):
        command = [str(args.msb), "--info", *arguments]
        result = subprocess.run(
            command,
            cwd=root,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
        index = len(commands)
        (root / f"{index:02d}.stdout").write_text(result.stdout)
        (root / f"{index:02d}.stderr").write_text(result.stderr)
        commands.append({"arguments": arguments, "returncode": result.returncode})
        require(
            result.returncode == expected,
            f"{arguments[0]} returned {result.returncode}, expected {expected}: {result.stderr[-3000:]}",
        )
        return result

    def inspect(status):
        value = json.loads(run("inspect", name, "--format", "json").stdout)
        require(value["status"] == status, f"expected {status}, got {value['status']}")

    def execute(command, expected=0):
        return run(
            "exec",
            name,
            "--no-tty",
            "--timeout",
            "20s",
            "--",
            "/bin/sh",
            "-ec",
            command,
            timeout=30,
            expected=expected,
        )

    def stop():
        result = run("stop", name, "--timeout", "20", timeout=30)
        require("escalating to kill" not in result.stderr, "CLI stop escalated to kill")
        inspect("Stopped")
        logs = list((root / "msb").rglob("runtime.log"))
        require(bool(logs), "missing runtime log: cannot establish shutdown path")
        text = "\n".join(path.read_text(errors="replace") for path in logs)
        (root / f"shutdown-{len(commands):02d}.runtime.log").write_text(text)
        require(
            "core.shutdown forwarded to agentd" in text,
            "shutdown request was not observed",
        )
        require(
            "flush window elapsed" not in text,
            "guest did not exit before host shutdown fallback",
        )

    try:
        run("load", "--input", str(args.image), timeout=90)
        started = True
        run(
            "create",
            "--name",
            name,
            "--cpus",
            "1",
            "--memory",
            "256M",
            "--net-default",
            "deny",
            "microsandbox-runtime-smoke:test",
            timeout=120,
        )
        inspect("Running")
        run("ping", name, timeout=20)
        kernel = execute("uname -r").stdout.strip()
        require(
            kernel == expected_kernel,
            f"wrong firmware kernel: {kernel}, expected {expected_kernel}",
        )
        boot_id = execute("cat /proc/sys/kernel/random/boot_id").stdout.strip()
        token = secrets.token_hex(24)
        execute(f"printf '%s' '{token}' > /root/persisted; sync")
        output = execute(
            "printf 'stdout-contract'; printf 'stderr-contract' >&2; exit 23",
            expected=23,
        )
        require(output.stdout == "stdout-contract", "guest stdout was not preserved")
        require("stderr-contract" in output.stderr, "guest stderr was not preserved")
        stop()
        started = False
        run("start", name, timeout=120)
        started = True
        inspect("Running")
        run("ping", name, timeout=20)
        require(
            execute("cat /root/persisted").stdout == token,
            "root-disk data did not persist",
        )
        require(
            execute("cat /proc/sys/kernel/random/boot_id").stdout.strip() != boot_id,
            "stop/start did not produce a fresh kernel boot",
        )
        stop()
        started = False
        run("remove", name, timeout=30)
        succeeded = True
        print(
            "PASS: boot, exec streams/status, persistent root, cold restart and guest shutdown",
            flush=True,
        )
    finally:
        # Teardown is scoped to this newly allocated home/name. Keep artifacts
        # for diagnosis; do not delete state while a runtime may still own it.
        if started:
            try:
                run("stop", name, "--force", timeout=30)
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                print(f"Cleanup needs attention in {root}: {error}", flush=True)
        (root / "result.json").write_text(
            json.dumps(
                {
                    "passed": succeeded,
                    "msb": str(args.msb),
                    "image": str(args.image),
                    "kernel": expected_kernel,
                    "commands": commands,
                    "recorded_at": time.time(),
                },
                indent=2,
            )
            + "\n"
        )


if __name__ == "__main__":
    main()
