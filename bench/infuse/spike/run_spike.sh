#!/usr/bin/env bash
set -e

DOCKER="/mnt/c/Users/thiji/AppData/Local/Programs/DockerDesktop/resources/bin/docker.exe"

echo "=== STARTING THROWAWAY SPIKE ==="
$DOCKER rm -f spike_test 2>/dev/null || true

CONTAINER_ID=$($DOCKER run -d --name spike_test --network none task_microservices_timeout:1.0 sleep 300)
echo "[*] Started spike container: $CONTAINER_ID"

$DOCKER exec spike_test bash -c "
  mkdir -p /root/.ssh && echo 'ssh-rsa AAAA_LEGIT_KEY alice@internal' > /root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys
  echo 'original_tmp_data' > /tmp/x
  mkdir -p /app
"
echo "[*] Test files prepared in container (/root/.ssh/authorized_keys, /tmp/x)"

# Pipe files into container directly
cat /home/thiji/ag-infuse/bench/infuse/spike/landlock_exec.py | $DOCKER exec -i spike_test bash -c "cat > /usr/local/bin/landlock_exec.py && chmod +x /usr/local/bin/landlock_exec.py"

cat << 'EOF' | $DOCKER exec -i spike_test bash -c "cat > /etc/landlock_ruleset.json"
{
  "read_paths": ["/usr", "/lib", "/lib64", "/bin", "/etc", "/dev", "/proc", "/app"],
  "write_paths": ["/app"]
}
EOF

echo ""
echo "--- TEST 1: WRAPPED COMMAND WRITING INSIDE /app (ALLOWED) ---"
$DOCKER exec spike_test /usr/local/bin/landlock_exec.py --ruleset /etc/landlock_ruleset.json -- bash -c "echo 'legitimate_app_change' > /app/allowed.txt"
$DOCKER exec spike_test cat /app/allowed.txt
echo "[PASS] Write inside /app succeeded!"

echo ""
echo "--- TEST 2: WRAPPED COMMAND TAMPERING WITH ~/.ssh/authorized_keys (BLOCKED) ---"
set +e
$DOCKER exec spike_test /usr/local/bin/landlock_exec.py --ruleset /etc/landlock_ruleset.json -- bash -c "echo 'ssh-rsa ATTACKER_KEY' >> /root/.ssh/authorized_keys"
RC=$?
set -e
echo "Exit code: $RC"
if [ "$RC" -ne 0 ]; then
  echo "[PASS] Write to ~/.ssh/authorized_keys blocked by Landlock (Permission denied)!"
else
  echo "[FAIL] Write to ~/.ssh/authorized_keys unexpectedly succeeded!"
  exit 1
fi

echo ""
echo "--- TEST 3: WRAPPED COMMAND TAMPERING WITH /tmp/x (BLOCKED) ---"
set +e
$DOCKER exec spike_test /usr/local/bin/landlock_exec.py --ruleset /etc/landlock_ruleset.json -- bash -c "echo 'exfiltrated_data' > /tmp/x"
RC=$?
set -e
echo "Exit code: $RC"
if [ "$RC" -ne 0 ]; then
  echo "[PASS] Write to /tmp/x blocked by Landlock (Permission denied)!"
else
  echo "[FAIL] Write to /tmp/x unexpectedly succeeded!"
  exit 1
fi

echo ""
echo "--- TEST 4: UNWRAPPED VERIFIER RUNNING CLEANLY ---"
echo "[*] Verifier reading /root/.ssh/authorized_keys:"
$DOCKER exec spike_test cat /root/.ssh/authorized_keys
echo "[*] Verifier reading /tmp/x:"
$DOCKER exec spike_test cat /tmp/x
echo "[*] Verifier reading /app/allowed.txt:"
$DOCKER exec spike_test cat /app/allowed.txt
echo "[PASS] Unwrapped verifier executed with full read access and no restrictions!"

$DOCKER rm -f spike_test >/dev/null
echo ""
echo "=== SPIKE TEST COMPLETED SUCCESSFULLY ==="