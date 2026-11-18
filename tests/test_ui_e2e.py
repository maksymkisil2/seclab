"""Browser E2E for the UI (Playwright + Chrome) against a live lab. Needs Docker; stub mode works offline.

Flow: launch dmz/hardened from the form -> audit 0 findings -> load flat firewall -> audit shows findings
-> broken ruleset rejected in the editor -> purge. Fails on any console error or CSP violation.
Screenshots go to $SECLAB_UI_SHOTS if set.
"""
from __future__ import annotations

import os
import re
import shutil
import threading
from pathlib import Path

import pytest

from seclab import ui
from seclab.lab import Lab
from seclab.runtime import Runtime
from seclab.web import teardown

pytestmark = pytest.mark.integration
playwright = pytest.importorskip("playwright.sync_api")
STUB = os.environ.get("SECLAB_STUB") == "1"
CHROME = shutil.which("google-chrome") or shutil.which("chromium")
SHOTS = os.environ.get("SECLAB_UI_SHOTS")
LAB = f"uie{os.getpid() % 1000}"


@pytest.fixture(scope="module")
def live(tmp_path_factory):
    rt = Runtime.detect()
    if not rt.available():
        pytest.skip("docker not reachable")
    os.environ.setdefault("SECLAB_HOME", str(tmp_path_factory.mktemp("ui-home")))
    with pytest.MonkeyPatch.context() as mp:
        if STUB:
            from seclab.images import node_image
            real = Lab.entry
            mp.setattr(Lab, "entry", lambda self, n: ["--entrypoint", "socat", node_image(), "TCP-LISTEN:22,fork", "x"]
                       if n.role == "ssh" else real(self, n))

            def stub_key(self, _rt):
                d = self.lab_dir / "ssh"
                d.mkdir(exist_ok=True)
                (d / "id_ecdsa").write_text("stub\n")
                (d / "id_ecdsa.pub").write_text("ecdsa-sha2-nistp384 AAAAstub x\n")
            mp.setattr(Lab, "_ensure_client_key", stub_key)
        httpd, _token, url = ui.make_server(0, rt=rt)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        yield rt, url
        httpd.shutdown()
        httpd.server_close()
        teardown(rt, LAB, purge=True)


def shot(page, name):
    if SHOTS:
        Path(SHOTS).mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(Path(SHOTS) / f"{name}.png"), full_page=True)


def test_ui_full_flow(live):
    rt, url = live
    sync = playwright.sync_playwright
    expect = playwright.expect
    with sync() as p:
        browser = p.chromium.launch(executable_path=CHROME, headless=True) if CHROME else p.chromium.launch()
        page = browser.new_page(viewport={"width": 1400, "height": 1000})
        problems = []
        def on_console(m):
            # the deliberately broken ruleset is answered with 400 by /fw: expected, everything else is not
            if m.type == "error" and not (" 400 " in m.text and m.location.get("url", "").endswith("/fw")):
                problems.append(f"{m.text} @ {m.location.get('url')}")
        page.on("console", on_console)
        page.on("pageerror", lambda e: problems.append(str(e)))
        page.on("dialog", lambda d: d.accept())

        page.goto(url)
        page.wait_for_selector("#conn.ok")
        assert "#t=" not in page.url                                     # token stripped from the address bar
        card = page.locator(".card", has=page.locator(".s-name", has_text=re.compile(r"^dmz$")))
        card.locator("select[name=profile]").select_option("hardened")
        card.locator("input[name=name]").fill(LAB)
        card.locator("input[name=port_offset]").fill("23000")
        card.locator("button[type=submit]").click()

        row = page.locator("#labs tbody tr", has_text=LAB)
        row.locator("td:nth-child(4) .pill.ok").wait_for(timeout=180_000)  # state 'up'
        row.click()
        page.wait_for_selector("#topo svg .t-node")
        assert page.locator("#topo .t-node").count() == 5
        assert "127.0.0.1" in page.locator("#access").inner_text()
        shot(page, "0-topology")

        row.get_by_role("button", name="audit").click()
        expect(page.locator("#check-summary")).to_have_text(re.compile(r" 0 finding"), timeout=180_000)
        assert page.locator("#check tbody tr.fail").count() == 0
        shot(page, "1-audit-hardened")

        page.locator(".tab[data-tab=fw]").click()
        expect(page.locator("#fw-live")).to_contain_text("table inet seclab")
        page.locator("#fw-levels button", has_text="vulnerable").click()
        page.wait_for_selector("#fw-msg.ok")
        shot(page, "2-firewall")
        page.locator(".tab[data-tab=check]").click()
        page.locator("#run-check").click()
        expect(page.locator("#check-summary")).to_have_text(re.compile(r" [1-9]\d* finding"), timeout=180_000)
        fails = page.locator("#check tbody tr.fail").all_inner_texts()
        assert any("web" in f and "db" in f and "5432" in f for f in fails)
        shot(page, "3-audit-flat")
        page.locator(".tab[data-tab=topo]").click()
        assert page.locator("#topo .t-node.bad").count() > 0
        shot(page, "4-topology-findings")

        page.locator(".tab[data-tab=fw]").click()
        page.locator("#fw-edit").fill("table inet seclab { chain broken { nonsense } }\n")
        page.locator("#fw-apply").click()
        page.wait_for_selector("#fw-msg.bad")
        assert "Error" in page.locator("#fw-msg").inner_text()

        row.get_by_role("button", name="purge").click()
        page.locator("#labs tbody tr", has_text=LAB).wait_for(state="detached", timeout=120_000)
        browser.close()

    assert not problems, problems
    assert not rt.container_ids(f"seclab.lab={LAB}")
