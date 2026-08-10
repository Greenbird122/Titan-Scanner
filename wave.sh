#!/bin/bash
# tmp_wave.sh <site1> [site2] [site3] — batch-scan sites concurrently, wait
# (bounded ~400s), then print a per-site summary. Reusable per wave.
cd /c/Users/HomePC/desktop/ai-agents/vuln-scanner || exit 1

slug() { echo "$1" | sed 's|https\?://||; s|/.*||; s|[^a-zA-Z0-9]|_|g'; }

for site in "$@"; do
  name=$(slug "$site")
  rm -f "/tmp/wave_$name.log"
  (./venv/Scripts/python.exe -u run.py --target "$site" > "/tmp/wave_$name.log" 2>&1 &)
done

# Wait for all scans to reach "Findings documented" (bounded ~400s).
waited=0
for i in $(seq 1 80); do
  done_count=0
  for site in "$@"; do
    name=$(slug "$site")
    if grep -q 'Findings documented' "/tmp/wave_$name.log" 2>/dev/null; then
      done_count=$((done_count + 1))
    fi
  done
  if [ "$done_count" -eq "$#" ]; then break; fi
  sleep 5
  waited=$((i * 5))
done

echo "=== wave done (waited ~${waited}s, $done_count/$# finished) ==="
for site in "$@"; do
  name=$(slug "$site")
  echo "--- $site ---"
  grep -E 'Loading target|Checkpoint detected|Crawl timed|Scan complete|Critical:|Duration:|Errors:' "/tmp/wave_$name.log" 2>/dev/null | tail -6
  if ! grep -q 'Findings documented' "/tmp/wave_$name.log" 2>/dev/null; then
    echo "    [!] scan did not finish in the window (log tail:)"
    tail -3 "/tmp/wave_$name.log" 2>/dev/null
  fi
done

# Clean up any lingering run.py processes from this wave.
wmic process where "name='python.exe' and commandline like '%run.py%'" delete >/dev/null 2>&1
