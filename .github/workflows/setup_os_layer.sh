#!/usr/bin/env bash
# Prepares a GitHub-hosted Ubuntu runner for the M6 OS layer as far as the host allows:
# builds the C helpers, starts a systemd --user manager (scopes need it) and lifts the
# AppArmor restriction on unprivileged user namespaces. Whatever is still missing
# (for example Landlock ABI < 6 on an older kernel) makes the os_layer tests skip with
# the concrete reason; nothing is reported as passing that did not run.
set -uo pipefail

sudo apt-get update -qq
sudo apt-get install -y -qq gcc libseccomp-dev dbus-user-session
make -C demo/security_monitor/app/governance/os_layer

sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 || true

uid="$(id -u)"
sudo loginctl enable-linger "$USER" || true
sudo systemctl start "user@${uid}.service" || true
echo "XDG_RUNTIME_DIR=/run/user/${uid}" >> "$GITHUB_ENV"
echo "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${uid}/bus" >> "$GITHUB_ENV"
export XDG_RUNTIME_DIR="/run/user/${uid}"
for _ in $(seq 1 30); do
  state="$(systemctl --user is-system-running 2>/dev/null || true)"
  case "$state" in running|degraded) break ;; esac
  sleep 1
done
echo "systemd --user: ${state:-unavailable}"
uname -r
exit 0
