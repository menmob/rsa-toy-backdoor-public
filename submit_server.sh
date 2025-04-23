#!/usr/bin/env bash
# generate_and_submit.sh

CLIENT_CMD="./rsa_gen"    
SERVER_URL="http://collabserver.org:5000/crack" 
TIMEOUT=10                        # seconds per submission
LOGFILE="submission.log"          # log file

# Prepare logfile (overwrite existing)
: > "$LOGFILE"

echo "Starting batch of 10 submissions at $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$LOGFILE"

# Initialize counters
count_created=0
count_cracked=0
count_failed=0
count_timeout=0
count_parse_fail=0

for i in {1..10}; do
  # 1) Generate a keypair
  output="$($CLIENT_CMD 2>&1)"
  n="$(printf '%s' "$output" | awk '/^n =/ {print $3}')"
  e="$(printf '%s' "$output" | awk '/^e =/ {print $3}')"

  if [[ -z $n || -z $e ]]; then
    echo "Pair #$i: creation failed" | tee -a "$LOGFILE"
    ((count_parse_fail++))
    continue
  fi
  ((count_created++))

  # 2) Submit to server
  echo -n "Pair #$i: created n=$n e=$e; submitting...; " | tee -a "$LOGFILE"
  resp="$(curl -sS -m "$TIMEOUT" -X POST "$SERVER_URL" \
    -H "Content-Type: application/json" \
    -d "{\"N\":\"$n\",\"E\":\"11$e\"}")"
  code=$?

  if [[ $code -eq 28 ]]; then
    echo "timeout (failed!)" | tee -a "$LOGFILE"
    ((count_timeout++))
  elif [[ $code -ne 0 ]]; then
    echo "failed (curl exit $code)" | tee -a "$LOGFILE"
    ((count_failed++))
  else
    d="$(printf '%s\n' "$resp" | sed -n 's/.*\"D\"[[:space:]]*:[[:space:]]*\"\([0-9A-Fa-f]*\)\".*/\1/p')"
    if [[ -n $d ]]; then
      echo "cracked d=$d" | tee -a "$LOGFILE"
      ((count_cracked++))
    else
      echo "failed: $resp" | tee -a "$LOGFILE"
      ((count_failed++))
    fi
  fi
done

echo "" | tee -a "$LOGFILE"
echo "Batch complete at $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$LOGFILE"
echo "Summary:" | tee -a "$LOGFILE"
echo "  Created successfully : $count_created" | tee -a "$LOGFILE"
echo "  Cracked              : $count_cracked" | tee -a "$LOGFILE"
echo "  Timeouts             : $count_timeout" | tee -a "$LOGFILE"
echo "  Failures             : $count_failed" | tee -a "$LOGFILE"
echo "  Generation failures    : $count_parse_fail" | tee -a "$LOGFILE"
