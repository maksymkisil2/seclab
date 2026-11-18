"""Shared container flag builder: labels, hard resource limits, lockdown options."""
from __future__ import annotations

from .profiles import ContainerPolicy

LABEL_MANAGED = "seclab.managed=1"


def lab_label(lab: str) -> str:
    return f"seclab.lab={lab}"


def container_flags(
    name: str,
    lab: str,
    role: str,
    policy: ContainerPolicy,
    *,
    cap_add: tuple[str, ...] = (),
    tmpfs: tuple[str, ...] = ("/tmp",),
) -> list[str]:
    args = [
        "--name", name, "--hostname", role,
        "--label", LABEL_MANAGED, "--label", lab_label(lab), "--label", f"seclab.role={role}",
        "--memory", policy.memory, "--memory-swap", policy.memory, "--cpus", policy.cpus,
        "--pids-limit", str(policy.pids), "--restart", "no", "--log-opt", "max-size=1m",
    ]
    if policy.read_only:
        args.append("--read-only")
        for path in tmpfs:
            args += ["--tmpfs", f"{path}:rw,noexec,nosuid,nodev,size=16m"]
    if policy.drop_all_caps:
        args += ["--cap-drop", "ALL"]
        for cap in cap_add:
            args += ["--cap-add", cap]
    if policy.no_new_privileges:
        args += ["--security-opt", "no-new-privileges:true"]
    if policy.user:
        args += ["--user", policy.user]
    return args
