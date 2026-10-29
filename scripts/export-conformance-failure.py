#!/usr/bin/env python3
"""Retain missing signed plan exports from this job's isolated local suite."""

import asyncio
import contextlib
import os
from pathlib import Path
import re
import sys
import tempfile


async def export_missing(client, directory):
    response = await client.httpclient.get(
        client.api_url_base + "api/plan", params={"length": 1000}, timeout=10,
    )
    response.raise_for_status()
    listing = response.json()
    plans = listing["data"]
    if len(plans) > 1000 or listing["recordsTotal"] != len(plans):
        raise ValueError("Incomplete plan listing")
    exported = 0
    for plan in plans:
        plan_id = plan["_id"]
        if not isinstance(plan_id, str) or not re.fullmatch(r"[A-Za-z0-9]{1,64}", plan_id):
            raise ValueError("Invalid plan identifier")
        # The pinned suite names its signed exports <plan-and-variant>-<id>-<date>.zip.
        if any(directory.glob(f"*-{plan_id}-*.zip")):
            continue
        with tempfile.TemporaryDirectory(prefix=".failure-export-", dir=directory) as temporary:
            with open(os.devnull, "w") as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
                archive = Path(await client.exportjson(plan_id, temporary))
            if archive.parent != Path(temporary) or archive.suffix != ".zip":
                raise ValueError("Invalid export path")
            destination = directory / archive.name
            if destination.exists():
                raise ValueError("Existing export must not change")
            archive.rename(destination)
            exported += 1
    return exported


async def export_local(directory):
    sys.path.insert(0, str(Path("conformance-suite/scripts").resolve()))
    from conformance import Conformance

    client = Conformance("https://conformance.localhost:8443/", None, False)
    try:
        await export_missing(client, Path(directory))
    finally:
        await client.httpclient.aclose()


def self_test():
    import io
    import subprocess
    import textwrap
    from types import SimpleNamespace
    import unittest
    from unittest.mock import AsyncMock

    class ExportTests(unittest.IsolatedAsyncioTestCase):
        async def test_missing_export_and_completed_export_unchanged(self):
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                complete = directory / "plan-Complete1-26-Oct-2026.zip"
                complete.write_bytes(b"existing signed archive")
                response = SimpleNamespace(
                    raise_for_status=lambda: None,
                    json=lambda: {"data": [{"_id": "Complete1"}, {"_id": "Failed1"}],
                                  "recordsTotal": 2},
                )

                async def export(plan_id, destination):
                    print("sensitive upstream diagnostic")
                    archive = Path(destination) / f"plan-{plan_id}-26-Oct-2026.zip"
                    archive.write_bytes(b"suite signed archive")
                    return str(archive)

                client = SimpleNamespace(
                    api_url_base="https://suite.invalid/",
                    httpclient=SimpleNamespace(get=AsyncMock(return_value=response)),
                    exportjson=AsyncMock(side_effect=export),
                )
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(await export_missing(client, directory), 1)
                self.assertEqual(output.getvalue(), "")
                self.assertEqual(complete.read_bytes(), b"existing signed archive")
                self.assertEqual((directory / "plan-Failed1-26-Oct-2026.zip").read_bytes(),
                                 b"suite signed archive")
                self.assertEqual(client.exportjson.await_args.args[0], "Failed1")

        async def test_invalid_or_truncated_listing_is_not_exported(self):
            for listing in ({"data": [{"_id": "../invalid"}], "recordsTotal": 1},
                            {"data": [{"_id": "Valid1"}], "recordsTotal": 2}):
                with self.subTest(listing=listing), tempfile.TemporaryDirectory() as temporary:
                    client = SimpleNamespace(
                        api_url_base="https://suite.invalid/",
                        httpclient=SimpleNamespace(get=AsyncMock(return_value=SimpleNamespace(
                            raise_for_status=lambda: None, json=lambda: listing,
                        ))),
                        exportjson=AsyncMock(),
                    )
                    with self.assertRaises(ValueError):
                        await export_missing(client, Path(temporary))
                    client.exportjson.assert_not_awaited()

        async def test_export_failure_does_not_leave_uploadable_partial_archive(self):
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                response = SimpleNamespace(
                    raise_for_status=lambda: None,
                    json=lambda: {"data": [{"_id": "Failed1"}], "recordsTotal": 1},
                )

                async def fail(plan_id, destination):
                    print("sensitive upstream diagnostic", file=sys.stderr)
                    (Path(destination) / "partial.zip").write_bytes(b"partial")
                    raise RuntimeError("sensitive upstream diagnostic")

                client = SimpleNamespace(
                    api_url_base="https://suite.invalid/",
                    httpclient=SimpleNamespace(get=AsyncMock(return_value=response)),
                    exportjson=AsyncMock(side_effect=fail),
                )
                output = io.StringIO()
                with contextlib.redirect_stderr(output), self.assertRaises(RuntimeError):
                    await export_missing(client, directory)
                self.assertEqual(output.getvalue(), "")
                self.assertEqual(list(directory.iterdir()), [])

        def test_workflow_preserves_original_failure_and_bounds_diagnostic(self):
            workflow = Path(".github/workflows/conformance.yml").read_text()
            tests = workflow.split("      - name: Run tests\n", 1)[1].split("\n      - name:", 1)[0]
            diagnostic = workflow.split("      - name: Export incomplete conformance plans\n", 1)[1].split("\n      - name:", 1)[0]
            self.assertIn("id: tests", tests)
            self.assertIn('run: make "cs-${{ matrix.profile }}-tests"', tests)
            self.assertNotIn("continue-on-error", tests)
            self.assertIn("if: ${{ failure() && steps.tests.outcome == 'failure' }}", diagnostic)
            self.assertIn("continue-on-error: true", diagnostic)
            self.assertIn("timeout --kill-after=5s 90s", diagnostic)
            self.assertLess(workflow.index("name: Export incomplete conformance plans"),
                            workflow.index("name: Upload test logs"))

        def test_failed_loopback_diagnostic_reaches_server_and_preserves_test_result(self):
            workflow = Path(".github/workflows/conformance.yml").read_text()
            startup = workflow.split("      - name: Start authorization server\n", 1)[1].split("\n      - name:", 1)[0]
            startup = textwrap.dedent(startup.split("run: |\n", 1)[1])
            tests = workflow.split("      - name: Run tests\n", 1)[1].split("\n      - name:", 1)[0]
            command = tests.split("run: ", 1)[1].strip().replace("${{ matrix.profile }}", "oidc")
            for result in (0, 7):
                with self.subTest(result=result), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    (root / "bin").mkdir()
                    executable = root / "bin/go"
                    executable.write_text('#!/bin/bash\nset -eu\n'
                                          '[[ "$*" == "run examples/oidc/main.go" ]]\n'
                                          'touch "$RUNNER_TEMP/server-started"\n')
                    executable.chmod(0o755)
                    stubs = '''
                        go() { printf '%s\\n' "$RUNNER_TEMP"; }
                        timeout() {
                          if [[ "$*" == *conformance-loopback-probe.go* ]]; then return 1; fi
                          return 0
                        }
                        make() { printf 'conformance_reached\\n'; return "$TEST_RESULT"; }
                    '''
                    completed = subprocess.run(
                        ["bash", "-c", textwrap.dedent(stubs) + startup +
                         '\nwait\n' + command + '\nprintf "after_conformance\\n"\n'],
                        env={**os.environ, "RUNNER_TEMP": temporary,
                             "PROFILE_FOLDER": "oidc", "TEST_RESULT": str(result)},
                        capture_output=True, text=True, timeout=5,
                    )
                    self.assertEqual(completed.returncode, result, completed.stderr)
                    self.assertIn('"status":"failed_or_incomplete"', completed.stdout)
                    self.assertTrue((root / "server-started").is_file())
                    self.assertIn("conformance_reached", completed.stdout)
                    self.assertEqual("after_conformance" in completed.stdout, result == 0)

        def test_fixture_hostname_is_coherent_with_active_config(self):
            obsolete_fixture_host = "localhost.emobix." + "co.uk"
            authutil = Path("examples/authutil/util.go").read_text()
            active_files = [
                Path("docker-compose.yml"),
                Path("examples/authutil/util.go"),
                Path("examples/oidc/main.go"),
                Path("examples/federation/main.go"),
                Path("scripts/export-conformance-failure.py"),
                Path("scripts/generate-conformance-certificates.sh"),
                Path("scripts/verify-conformance-certificates.sh"),
                Path("scripts/verify-conformance-pin.sh"),
                Path("scripts/test-conformance-certificates.sh"),
                Path("README.md"),
                *Path("docs").rglob("*.md"),
                *Path("examples").rglob("config.json"),
            ]
            for path in active_files:
                with self.subTest(path=path):
                    content = path.read_text()
                    self.assertNotIn(
                        obsolete_fixture_host, content,
                        msg=f"{path} retains the obsolete fixture hostname",
                    )

            compose = Path("docker-compose.yml").read_text()
            self.assertIn("https://conformance.localhost:8443", compose)
            self.assertIn("https://conformance.localhost:8444", compose)
            self.assertIn("conformance.localhost:host-gateway", compose)
            self.assertIn(
                'Issuer                   string = "https://auth.localhost"',
                authutil,
            )

    result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(ExportTests))
    return not result.wasSuccessful()


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        sys.exit(self_test())
    if len(sys.argv) == 2:
        try:
            # The pinned exporter logs response bodies and URLs on retry; never echo them.
            with open(os.devnull, "w") as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
                asyncio.run(export_local(sys.argv[1]))
        except Exception:
            print("conformance_failure_export status=failed", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)
    sys.exit("Expected export directory")
