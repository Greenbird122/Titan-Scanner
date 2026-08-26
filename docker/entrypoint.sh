#!/usr/bin/env bash
# Titan Scanner container entrypoint.
#
# Starts two processes so `docker compose up` = lab + C2 listener ready:
#   - the vulnerable lab on 0.0.0.0:5000 (validation target)
#   - the C2 listener on 0.0.0.0:8770  (agents poll it; REPLs remote-join it)
#
# The lab is started via an import wrapper (not `python local_lab/app.py`) so
# Flask's debug reloader never spawns a watcher process — containers want a
# single tidy process tree. The listener runs in the foreground; a SIGTERM
# from `docker compose stop` tears down the lab and exits cleanly.
set -euo pipefail

echo "[+] Titan Scanner container starting"
echo "[+]  - vulnerable lab  -> http://127.0.0.1:5000"
echo "[+]  - C2 listener     -> http://127.0.0.1:8770"

python -c "import sys; sys.path.insert(0, 'local_lab'); from app import app; app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)" &
LAB_PID=$!

# Readiness probe: a dead lab behind a "running" container is a silent trap
# (backgrounded jobs never trip `set -e`). Abort fast so `restart:
# unless-stopped` retries instead of serving a half-dead stack.
ready=0
for _i in $(seq 1 20); do
    if curl -s -m 1 -o /dev/null http://127.0.0.1:5000/ 2>/dev/null; then
        ready=1
        break
    fi
    if ! kill -0 "$LAB_PID" 2>/dev/null; then
        break
    fi
    sleep 0.5
done
if [ "$ready" != "1" ]; then
    echo "[!] lab did not become ready — aborting (see docker compose logs titan)" >&2
    kill "$LAB_PID" 2>/dev/null || true
    exit 1
fi
echo "[+] lab ready on http://127.0.0.1:5000"

shutdown() {
    echo "[+] shutting down (lab pid $LAB_PID)"
    kill "$LAB_PID" 2>/dev/null || true
    exit 0
}
trap shutdown INT TERM

python titan_exploit_cli.py listener --host 0.0.0.0 --port 8770 --store findings
