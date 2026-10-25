# M6: OS-bound agent loop (WSL2) - design notes and limitations

Status: M6.1 + M6.1b implemented; M6.2 (evaluation v3) in progress.

## Flow

user prompt -> intake (task + boundary) -> workspace -> `systemd-run --user --scope`
(task <-> cgroup read back from `/proc/<pid>/cgroup`) -> per-task broker Unix socket +
egress proxy -> **sensor -> seccomp -> Landlock -> agent shim** -> correlator ->
evaluator -> graduated response -> Task Receipt v0 (`receipts/<task_id>.json`).

Code: `demo/security_monitor/app/governance/{launcher,agent_shim,broker_rpc,correlator,receipt,redaction}.py`,
`os_layer/{sandbox_spec,cgroup_ctl}.py`, `os_layer/{sensor,landlock_enforcer}.c`.
Scripts: `scripts/m6_preflight.py`, `scripts/verify_receipt.py`,
`scripts/m6_concurrency_check.py`, `scripts/m6_concurrency_check_v2.py`.

## Sandbox compiled from the boundary

- `files_read`: per-file read rules (globs expanded at launch; sensitive-pattern files excluded).
- `output/`, `scratch/`: task-owned, directory-level read-write (temp-file + rename, `sed -i`).
  Writes there to names not in `files_write` are recorded INSIDE with a note.
- Other `files_write` targets: per-file rules (pre-created empty); glob write patterns: directory rules.
- `granted/`: pre-authorised, read-only; approved expansions are delivered there by copy.
- Task `tmp/`; system read/exec paths; TCP connect only to the egress proxy port.
- User + mount namespaces, tmpfs over `/run/user/<uid>`, Landlock ABI-6 signal and
  abstract-socket scoping, no `/tmp`, fail-closed in ENFORCE.
- `ToolBroker.run_command` also uses the boundary-compiled `--rules` mode. The M4
  `--workspace` layout mode remains only for the M4 tests and `overhead_benchmark.py`;
  results produced in it carry `isolation_level="legacy_workspace"`, and the launcher
  refuses to run conditions C/D unless the enforcer reports `--rules` mode.

## Freeze triggers (cgroup.freeze, then kill after `freeze_timeout_s`)

sensor exits early; isolation below the ENFORCE requirement; broker socket dies;
an OUTSIDE OS access succeeds under ENFORCE. Each has a test.

## Measured (Checkpoint 1 / M6.1b)

- Concurrency v1: 20 rounds x 2 tasks (scripted mock LLM), 14,240 events,
  0 cross-attributions, 0 UNATTRIBUTED; overlap only ~0.7 s per round.
- Concurrency v2: 20 rounds x 2 tasks, ~10.5 s overlap per round, interleaved file,
  Unix-socket, denied-TCP and proxied HTTP work plus a background child that outlives
  the shim: 83,720 events, 0 cross-attributions, 0 UNATTRIBUTED, 44,400 background-child
  events all attributed to the right task (25,835 after the shim's last event).

## Limitations

- **Single-use delivery is not kernel-enforced.** A HIGH (single-use) grant delivered into
  `granted/` is removed after the *first open observed by the sensor*. Between that open
  and the removal the file is still readable, and an access the sensor does not observe
  would not trigger removal. Landlock cannot express "read once".
- **`bind()` is not observable on this WSL2 machine.** A seccomp filter installed by WSL's
  init (inherited by every process) outranks `SECCOMP_RET_TRACE` for `bind`. Landlock
  still denies TCP bind (tested); the preflight reports this as WARN.
- **Not traced:** the stat family, `read`/`write` on already-open fds, `sendto`/`sendmsg`
  without a destination address (connected sockets), `listen`, `accept`, `ptrace`, `kill`.
  E.g. uutils `cat` of a missing file performs a `statx` and no `open`.
- **UDP is not mediated by Landlock** (TCP connect/bind only). A UDP send that succeeds is
  recorded OUTSIDE with `prevented_by=none` and, under ENFORCE, freezes the task.
- The ptrace sensor is observation only (Phase 0); eBPF is planned for M7.
- One task per cgroup; shared long-lived agents are M9. Windows-native is not enforced.
- Receipts are hash-chained, not signed.
- Write targets outside `output/`/`scratch/` are pre-created empty (Landlock rules attach
  to existing inodes).
