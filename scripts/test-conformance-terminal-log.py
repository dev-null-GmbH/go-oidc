#!/usr/bin/env python3
"""Exercise the exact pinned suite read and analyzer without starting a conformance run."""
import ast
import asyncio
import fnmatch
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock


async def main(runner, failures):
    tree = ast.parse(runner.read_bytes())
    names = {"get_terminal_test_log", "analyze_result_logs"}
    functions = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names]
    sleep = AsyncMock()
    timeout = Mock(wraps=asyncio.timeout)
    fixture = {"asyncio": SimpleNamespace(sleep=sleep, timeout=timeout), "fnmatch": fnmatch}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(runner), "exec"), fixture)
    read, analyze = (fixture[name] for name in ("get_terminal_test_log", "analyze_result_logs"))
    module, module_id = "oidcc-server-rotate-keys", "synthetic-exact-module"
    info = {"status": "FINISHED", "result": "FAILED"}
    partial = ([{"result": "SUCCESS", "src": "synthetic"}] * 13) + ([{"src": "fixture"}] * 27)
    complete = [*partial, {"result": "FAILURE", "src": "VerifyNewJwksHasNewSigningKey"}]

    async def check(name, state, responses, expected_reads):
        sleep.reset_mock()
        timeout.reset_mock()
        fetch = AsyncMock(side_effect=responses)
        logs = await read(SimpleNamespace(get_test_log=fetch), name, module_id, state)
        assert fetch.await_count == expected_reads
        assert all(call.args == (module_id,) for call in fetch.await_args_list)
        assert sleep.await_count == expected_reads - 1
        assert all(call.args == (0.2,) for call in sleep.await_args_list)
        if expected_reads > 1:
            timeout.assert_called_once_with(2)
        return logs

    def counts(logs):
        counters = dict.fromkeys(("EXPECTED_FAILURES", "UNEXPECTED_FAILURES", "EXPECTED_FAILURES_NOT_HAPPEN"), 0)
        analyze(module_id, module, {"response_type": "code"}, "FAILED", {"config_file": "./examples/oidc/config.json"},
                logs, json.loads(failures.read_bytes()), [], counters)
        return counters

    assert counts(await check(module, info, [partial, complete], 2)) == {
        "EXPECTED_FAILURES": 1, "UNEXPECTED_FAILURES": 0, "EXPECTED_FAILURES_NOT_HAPPEN": 0,
    }
    assert counts(await check(module, info, [partial] * 6, 6))["EXPECTED_FAILURES_NOT_HAPPEN"] == 1
    assert counts(await check(module, info, [[*complete, {"result": "FAILURE", "src": "UnexpectedCondition"}]], 1))[
        "UNEXPECTED_FAILURES"
    ] == 1
    await check("another-module", info, [partial], 1)
    await check(module, {**info, "result": "PASSED"}, [partial], 1)
    await check(module, {**info, "status": "INTERRUPTED"}, [partial], 1)
    fixture["asyncio"].timeout = lambda seconds: asyncio.timeout(0.001)
    calls = 0

    async def delayed_fetch(test_id):
        nonlocal calls
        assert test_id == module_id
        calls += 1
        if calls == 1:
            return partial
        await asyncio.sleep(60)

    logs = await read(SimpleNamespace(get_test_log=delayed_fetch), module, module_id, info)
    assert calls == 2 and counts(logs)["EXPECTED_FAILURES_NOT_HAPPEN"] == 1
    print("Conformance terminal read preserves exact conditions and rejects incomplete logs after its bounded retry")


if __name__ == "__main__":
    asyncio.run(main(Path(sys.argv[1]), Path(sys.argv[2])))
