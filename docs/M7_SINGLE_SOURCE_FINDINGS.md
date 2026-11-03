# M7 step 1: one boundary list for the tool layer and the kernel layer - findings

Status: implemented on branch `m7-single-source` (opt-in `boundary_model="v1.1"`;
the frozen evaluation path `v1` is unchanged). Regression run on the new path pending.

## Design

`resolve_boundary(boundary, workspace, grants)` (`app/governance/resolved_boundary.py`)
turns a `TaskBoundary` into one list of entries `(absolute canonical path, file|dir,
{read, write, create, remove})`. The broker (`ResolvedBoundaryEvaluator`) and the
Landlock compiler (`compile_landlock_rules_resolved`) both read only that list.

- Alias rule: a bare `n` is dropped when `input/n` (reads) or `output/n` (writes) is
  also listed. No other aliasing; every other entry names exactly one path.
- Entries must be canonical relative paths inside the workspace: absolute, `..`, `./`,
  symlinked paths and the reserved names `tmp/ runtime/ granted/ broker.sock` are rejected.
- Exact write entries are one file; `D/*` / `D/**` become a directory rule; other write
  globs are narrowed to existing files; a bare `*` grants nothing. Read globs are expanded
  once over regular, non-symlink files, without sensitive names.
- `output/` and `granted/` are readable; `scratch/` is not granted.
- `BoundaryDerivationV1_1` = V1 without the bare output alias, and with the code-task
  write globs `src/**` / `tests/**` replaced by the named files when the request names
  files in that directory (a glob is kept only when no narrower rule is possible).
- Selection: `TaskSpec.boundary_model` (default `"v1"`); the Run page and the launcher
  CLI use `"v1.1"`; `evaluate_v3.py --boundary-model` (default `v1`).

## Declared limitations

1. **Sensitive names beneath a directory write rule.** For a write glob such as `src/**`
   the broker refuses writes to sensitive names (`src/.env`), but a Landlock directory
   rule cannot exclude one name. Accepted as a limitation and reported in each compile
   report under `kernel_cannot_express`. V1.1 avoids deriving such globs when a per-file
   rule is possible.
2. **Write expansion is not supported yet.** Landlock rules cannot be widened after
   `restrict_self`, so an approved `file_write` expansion cannot reach the kernel layer.
   On the v1.1 path it is refused in both layers. Approved `file_read` expansions are
   delivered by copy and are readable only as `granted/<path>`.
3. **Runtime support is kernel-only.** System paths, the interpreter, `tmp/` (TMPDIR,
   HOME), `runtime/` and the broker socket are granted by the kernel compiler so the
   process can run; they are never boundary entries and the broker refuses them.

## Differential test (`tests/test_m7_differential.py`)

Every v3 scenario boundary (derived and gold, 352) plus 200 random boundaries (seed
20261103), about 100 probe paths each (aliases, case variants, `..`, `./`, symlinks,
grants, nested paths, outside paths). Each probe is decided by the broker and performed
for real under `landlock_enforcer --mode enforce`.

| path | boundaries | probes | compared | mismatches |
|---|---|---|---|---|
| v1.1 (resolved) | 552 | 60,624 | 43,352 | **0** (60 declared residuals: `src/.env` under `src/**`) |
| v1 (frozen M6, `M7_DIFF_PATH=old`) | 552 | 61,680 | 48,662 | **9,091** |

No weakening: over all probes, the v1.1 broker never allows what the v1 broker or v1
kernel denied, and the v1.1 kernel never allows what the v1 kernel denied. The 2,236
probes where the v1.1 kernel allows something the v1 broker denied are runtime support
(2,176) and the declared residual (60), both also allowed by the v1 kernel.

## Old-path (frozen M6) disagreements by cause

| cause | probes (scenario / random) | direction | example |
|---|---|---|---|
| bare output alias | 549 (528 / 21) | broker allow, kernel deny | write `summary.txt` |
| case variants | 1,037 (528 / 509) | broker allow, kernel deny | write `OUTPUT/SUMMARY.TXT` |
| `output/` directory rule | 2,263 (1,120 / 1,143) | **broker deny, kernel allow** | write `output/sales_1.csv` |
| nested paths under `output/` | 2,005 (1,120 / 885) | **broker deny, kernel allow** | write `output/sub/sales_1.csv` |
| `scratch/` directory rule | 2,099 (1,408 / 691) | **broker deny, kernel allow** | read `scratch/notes.txt` |
| write glob `*` (kernel skips it) | 470 (0 / 470) | broker allow, kernel deny | write `other.csv` |
| symlinks | 217 (0 / 217) | **broker deny, kernel allow** | read `../outside/secret.txt` |
| symlinks | 92 (0 / 92) | broker allow, kernel deny | read `output/link_to_input.csv` |
| granted files (kernel cannot widen) | 161 (64 / 97) | broker allow, kernel deny | read `reference/target_sales_01.csv` |
| bare directory entry (`input`) | 138 (0 / 138) | **broker deny, kernel allow** | read `input/api_token.txt` |
| write-glob directory rule | 60 (0 / 60) | **broker deny, kernel allow** | write `src/.env` |
| `..` | 0 | - | `..` entries are rejected by both layers |

Broker-deny / kernel-allow gaps in the frozen system:

- **`output/` and `scratch/`** (reachable in every scenario boundary): any unlisted
  file or new subdirectory in `output/` is writable from the shell, including
  `output/.env`; `scratch/` is readable and writable. The correlator records these as
  INSIDE, so nothing freezes. These gaps stay inside the workspace.
- **Symlink escape** (random boundaries only; needs a symlink in the workspace at
  launch, which the frozen scenarios never have): with `files_read: ["input/*"]` and
  `input/link_out.txt -> /…/outside/secret.txt`, the old compiler's glob matches the
  symlink, and the enforcer attaches the read rule to the *target* inode. The outside
  file is then readable inside the sandbox under its own path (`../outside/secret.txt`,
  the absolute path), while the broker refuses it. 125 probes in 37 random boundaries,
  all with an `input/*` or `**` read glob. The resolver skips symlinks.
- **Bare directory read entry** (`input`): the kernel grants the whole directory,
  including `input/.env` and `input/api_token.txt`, which the broker refuses.
- **`src/.env` under `src/**`**: same as declared limitation 1.

The frozen path is not changed; these are documented, not fixed, in v1.

## Frozen reproducibility

`scripts/m7_frozen_boundary_check.py` re-derives five frozen trials with V1
(injected_indirect_01/09 C, E1b injected_indirect_04 C, legit_anticipated_03 C,
legit_unanticipated_05 C): all byte-identical to the receipts' `initial_boundary`,
prompts matched by `prompt_sha256`. The frozen runs took `files_read` from the gold
boundary; reproducing them needs `--boundary-source gold` (today's default `derived`
adds `reference/target_tickets_05.csv` for legit_unanticipated_05).
