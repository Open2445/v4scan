#!/usr/bin/env bash
set -u
cd "F:/Program Files/workbuddy ai/2026-08-31-13-11-24/v4-scan"
BIN="$(pwd)/target/release/v4scan.exe"
PY="C:/Users/Vishnu/.workbuddy-ai/binaries/python/versions/3.13.12/python.exe"
WORK="_cond3/work"
RES="_cond3/results.tsv"
: > "$RES"
mkdir -p "$WORK"
scanned=0; failed=0
while IFS='|' read -r name ver rest; do
  [ -z "$name" ] && continue
  safe=$(echo "$name" | tr '/@' '__')
  out="$WORK/$safe"
  rm -rf "$out"; mkdir -p "$out"
  tgz=$( ( cd "$out" && timeout 45 npm pack "$name@$ver" --silent 2>/dev/null ) | tail -1 )
  if [ -z "$tgz" ] || [ ! -f "$out/$tgz" ]; then
    echo -e "$name\tPACK_FAIL\t\t\t" >> "$RES"
    failed=$((failed+1)); continue
  fi
  ( cd "$out" && tar -xzf "$tgz" 2>/dev/null && rm -f "$tgz" )
  scanout=$(timeout 30 "$BIN" "$out/package" 2>/dev/null)
  if [ -z "$scanout" ]; then
    echo -e "$name\tSCAN_FAIL\t\t\t" >> "$RES"
    failed=$((failed+1)); continue
  fi
  summary=$(printf '%s' "$scanout" | "$PY" -c "import sys,json
try:
    d=json.load(sys.stdin); s=d['summary']
    ids=[f['id'] for f in d['findings'] if f['severity'] in ('high','critical')]
    print('\t'.join([str(s['findings']),str(s['high']),str(s['critical']),','.join(ids)]))
except Exception as e:
    print('PARSE_FAIL')")
  echo -e "$name\t$summary" >> "$RES"
  scanned=$((scanned+1))
done < "_cond3/corpus.txt"
echo -e "\n# scanned=$scanned failed=$failed" >> "$RES"
echo "DONE"
