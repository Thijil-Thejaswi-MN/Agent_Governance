#!/usr/bin/env bash
set -e

DOCKER="/mnt/c/Users/thiji/AppData/Local/Programs/DockerDesktop/resources/bin/docker.exe"

$DOCKER rm -f immutability_test 2>/dev/null || true

CONTAINER_ID=$($DOCKER run -d --name immutability_test --network none task_microservices_timeout:1.0 sleep 300)

$DOCKER exec immutability_test bash -c "mkdir -p /tmp/scratch_task_12 /app"

# Pipe files into container directly
cat /home/thiji/ag-infuse/bench/infuse/spike/landlock_exec.py | $DOCKER exec -i immutability_test bash -c "cat > /usr/local/bin/landlock_exec.py && chmod 555 /usr/local/bin/landlock_exec.py"

cat << 'EOF' | $DOCKER exec -i immutability_test bash -c "cat > /etc/landlock_ruleset.json && chmod 444 /etc/landlock_ruleset.json"
{
  "read_paths": ["/usr", "/lib", "/lib64", "/bin", "/etc", "/dev", "/proc", "/app", "/tmp/scratch_task_12"],
  "write_paths": ["/app", "/tmp/scratch_task_12"]
}
EOF

echo "--- TEST A: ATTEMPT TO MODIFY LAUNCHER (/usr/local/bin/landlock_exec.py) ---"
set +e
$DOCKER exec immutability_test /usr/local/bin/landlock_exec.py --ruleset /etc/landlock_ruleset.json -- bash -c "echo '# tampered' > /usr/local/bin/landlock_exec.py"
RC1=$?
set -e
echo "Exit code: $RC1"
if [ "$RC1" -ne 0 ]; then
  echo "[PASS] Launcher modification blocked by Landlock!"
else
  echo "[FAIL] Launcher was modified!"
  exit 1
fi

echo "--- TEST B: ATTEMPT TO MODIFY RULESET (/etc/landlock_ruleset.json) ---"
set +e
$DOCKER exec immutability_test /usr/local/bin/landlock_exec.py --ruleset /etc/landlock_ruleset.json -- bash -c "echo '{"all": "allowed"}' > /etc/landlock_ruleset.json"
RC2=$?
set -e
echo "Exit code: $RC2"
if [ "$RC2" -ne 0 ]; then
  echo "[PASS] Ruleset modification blocked by Landlock!"
else
  echo "[FAIL] Ruleset was modified!"
  exit 1
fi

echo "--- TEST C: ATTEMPT TO WRITE TO /tmp OUTSIDE SCRATCH DIR ---"
set +e
$DOCKER exec immutability_test /usr/local/bin/landlock_exec.py --ruleset /etc/landlock_ruleset.json -- bash -c "echo 'bad' > /tmp/sys_info.txt"
RC3=$?
set -e
echo "Exit code: $RC3"
if [ "$RC3" -ne 0 ]; then
  echo "[PASS] Write to /tmp outside scratch dir blocked by Landlock!"
else
  echo "[FAIL] Write to /tmp outside scratch dir succeeded!"
  exit 1
fi

echo "--- TEST D: WRITE TO SCRATCH DIR (/tmp/scratch_task_12) ---"
$DOCKER exec immutability_test /usr/local/bin/landlock_exec.py --ruleset /etc/landlock_ruleset.json -- bash -c "echo 'scratch data' > /tmp/scratch_task_12/test.tmp"
$DOCKER exec immutability_test cat /tmp/scratch_task_12/test.tmp
echo "[PASS] Write to scratch dir succeeded!"

$DOCKER rm -f immutability_test >/dev/null
echo "=== ALL IMMUTABILITY & SCRATCH TESTS PASSED ==="
