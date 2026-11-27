"""Benchmark lab lifecycle on a generated network (stub images, sshd replaced): python3 selftest/bench.py
Env: DEPTS (default 4), PROFILE (default vulnerable). Prints time per docker sub-command and phase."""
import collections
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from seclab import generator
from seclab.images import node_image
from seclab.lab import Lab, check
from seclab.profiles import get_profile
from seclab.runtime import Runtime
from seclab.web import teardown

real_entry = Lab.entry
Lab.entry = lambda self, n: (["--entrypoint", "socat", node_image(), "TCP-LISTEN:22,fork", "x"]
                             if n.role == "ssh" else real_entry(self, n))
def stub_key(self, _rt):
    d = self.lab_dir / "ssh"; d.mkdir(exist_ok=True)
    (d / "id_ecdsa.pub").write_text("ecdsa-sha2-nistp384 AAAAstub x\n")
Lab._ensure_client_key = stub_key

stats = collections.defaultdict(lambda: [0, 0.0])
orig = Runtime.run
def timed(self, *args, **kw):
    t = time.monotonic()
    try:
        return orig(self, *args, **kw)
    finally:
        key = " ".join(a for a in args[:2] if not a.startswith("-"))
        stats[key][0] += 1; stats[key][1] += time.monotonic() - t
Runtime.run = timed

p = generator.Params(name="prof", departments=int(os.environ.get("DEPTS", 4)), hosts_per_dept=3, sites=3,
                     public_sites=2, mail=True, seed=3)
rt = Runtime.detect()
lab = Lab("prof", generator.build(p), get_profile(os.environ.get("PROFILE", "vulnerable")), "x", 30000, "medium", 7)
teardown(rt, "prof", True)
phases = {}
for name, fn in [("up", lambda: lab.up(rt)), ("check", lambda: check(rt, lab)), ("down", lambda: teardown(rt, "prof", True))]:
    stats.clear(); t = time.monotonic(); res = fn(); phases[name] = time.monotonic() - t
    print(f"== {name}: {phases[name]:.1f}s  containers={generator.estimate(p)['containers']}")
    for k, (n, s) in sorted(stats.items(), key=lambda x: -x[1][1])[:8]:
        print(f"   {k:<22} x{n:<4} {s:6.1f}s")
    if name == "check":
        print("   findings:", sum(not r.ok for r in res), "of", len(res))
