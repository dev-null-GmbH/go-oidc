#!/usr/bin/env python3
"""Exercise the pinned suite's log retrieval and analyzer without a conformance run."""
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
    names = {"IncompleteTestLog", "order_test_log", "get_terminal_test_log", "analyze_result_logs"}
    definitions = [node for node in tree.body if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                   and node.name in names]
    sleep = AsyncMock()
    timeout = Mock(wraps=asyncio.timeout)
    fixture = {"asyncio": SimpleNamespace(sleep=sleep, timeout=timeout), "fnmatch": fnmatch}
    exec(compile(ast.Module(body=definitions, type_ignores=[]), str(runner), "exec"), fixture)
    read = fixture["get_terminal_test_log"]
    analyze = fixture["analyze_result_logs"]
    module, module_id = "oidcc-server-rotate-keys", "synthetic-exact-module"

    # The native log endpoint can return a result before its block start at
    # the same millisecond. The expected failure is already in the raw log.
    start = {"startBlock": True, "src": "-START-BLOCK-", "blockId": "tied", "msg": "fixture", "time": 10}
    result = {"result": "SUCCESS", "src": "MapJwksToValidationLocation", "blockId": "tied", "time": 10}
    expected = {"result": "FAILURE", "src": "VerifyNewJwksHasNewSigningKey", "time": 11}
    tied = [result, start, expected]
    incomplete = [result, expected]
    ordered = [start, result, expected]

    async def check(responses, expected_reads, error=None):
        sleep.reset_mock()
        timeout.reset_mock()
        fetch = AsyncMock(side_effect=responses)
        try:
            logs = await read(SimpleNamespace(get_test_log=fetch), module_id)
        except ValueError as exc:
            if error is None or error not in str(exc):
                raise
            logs = None
        else:
            assert error is None
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

    assert await check([tied], 1) == ordered
    assert tied == [result, start, expected]
    assert counts(ordered) == {"EXPECTED_FAILURES": 1, "UNEXPECTED_FAILURES": 0, "EXPECTED_FAILURES_NOT_HAPPEN": 0}
    assert await check([incomplete, tied], 2) == ordered
    await check([incomplete] * 6, 6, "Missing conformance log block start")
    await check([[result, {**start, "time": 11}, expected]], 1, "different timestamp")
    await check([[start, result, dict(start), expected]], 1, "Duplicate")
    assert counts(await check([[result, start]], 1))["EXPECTED_FAILURES_NOT_HAPPEN"] == 1
    assert counts(await check([[*tied, {"result": "FAILURE", "src": "UnexpectedCondition", "time": 12}]], 1))[
        "UNEXPECTED_FAILURES"
    ] == 1

    fixture["asyncio"].timeout = lambda seconds: asyncio.timeout(0.001)
    calls = 0

    async def delayed_fetch(test_id):
        nonlocal calls
        assert test_id == module_id
        calls += 1
        if calls == 1:
            return incomplete
        await asyncio.sleep(60)

    try:
        await read(SimpleNamespace(get_test_log=delayed_fetch), module_id)
    except TimeoutError:
        assert calls == 2
    else:
        raise AssertionError("incomplete terminal log passed its timeout")
    print("Conformance log order preserves every condition and rejects incomplete or invalid block order")


if __name__ == "__main__":
    asyncio.run(main(Path(sys.argv[1]), Path(sys.argv[2])))
