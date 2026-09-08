#!/usr/bin/env bash
# RESUME: process only corpus packages NOT already present in results.tsv.
# Does NOT wipe the existing results file.
set -u
cd "F:/Program Files/workbuddy ai/2026-08-31-13-11-24/v4-scan"
BIN="$(pwd)/target/release/v4scan.exe"
PY="C:/Users/Vishnu/.workbuddy-ai/binaries/python/versions/3.13.12/python.exe"
WORK="_cond3/work"
RES="_cond3/results.tsv"
CORPUS="_cond3/corpus.txt"

mkdir -p "$WORK"

# Build set of already-done package names from existing results.tsv
declare -A done_map
while IFS=$'\t' read -r name rest; do
  [ -z "$name" ] && continue
  # skip footer/comment lines
  [[ "$name" == \#* ]] && continue
  done_map["$name"]=1
done < "$RES"

processed=0; skipped=0; failed=0
while IFS='|' read -r name ver rest; do
  [ -z "$name" ] && continue
  if [ -n "${done_map[$name]:-}" ]; then
    skipped=$((skipped+1)); continue
  fi
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
  processed=$((processed+1))
done < "$CORPUS"
echo -e "# resume: processed=$processed skipped=$skipped failed=$failed" >> "$RES"
echo "RESUME DONE"
