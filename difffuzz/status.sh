#!/usr/bin/env bash
# One-shot status of the differential fuzzing run.
cd "$(dirname "$0")"
echo "time: $(date '+%F %T %Z')  load: $(cut -d' ' -f1-3 /proc/loadavg)"
docker ps -a --filter name=sha1fuzz- --format '{{.Names}} {{.Status}}'
for f in logs/*.log; do
  [ -e "$f" ] || continue
  n=$(basename "$f" .log)
  case $n in
  hunt-*) last=$(tail -1 "logs/$n.progress" 2>/dev/null) ;;
  *) last=$(grep -a 'fuzz: elapsed' "$f" | tail -1) ;;
  esac
  fail=$(grep -a -m1 -E -- '--- FAIL|panic:|Failing input|HUNT FAILURE' "$f")
  echo "$n: ${last:-no progress yet}${fail:+  FAIL: $fail}"
done
for d in testdata/fuzz/*/; do [ -d "$d" ] && echo "crashers $(basename "$d"): $(ls "$d" | wc -l) file(s)"; done
for d in .cache/fuzz/*/; do [ -d "$d" ] && echo "corpus $(basename "$d"): $(ls "$d" | wc -l) file(s)"; done
echo "failures dir: $(ls failures 2>/dev/null | wc -l) file(s)"
