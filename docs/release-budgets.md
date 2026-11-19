# Ресурсная приёмка Rivect (AC-003)

## Действующий критерий для v2

Решение владельца: числовых порогов для v2 нет. Для стабильного релиза
обязателен свежий машиночитаемый отчёт каждого нативного кандидата
(Linux x86_64 и macOS arm64). Отсутствие, неполнота или несовпадение
отчёта с артефактом блокирует выпуск. Установка, откат, sandbox и остальные
критерии приёмки не меняются.

- Размер в байтах: точный архив, передаваемый издателю, и сумма размеров
  файлов установленной версии с квитанцией.
- PTY: 20 свежих процессов на 160×50 без очистки кэша ОС; запуск до
  видимого первого ввода, эхо клавиши и восстановление терминала после
  Ctrl+C в покое.
- Под нагрузкой: по 20 свежих процессов с короткой (1 задача) и длинной
  (100 задач) историей, старым diff и продолжающимся локальным SSE.
  Замеряем эхо ввода, отмену до закрытия SSE и записи состояния, RSS
  дерева процессов после эха. Отчёт хранит значения отдельных прогонов,
  p50/p95 по задержкам и максимум наблюдённого RSS; не называет его
  непрерывно измеренным пиком. Сеть провайдера не используется.
- Привязка: версия схемы, OS/arch, commit/run, SHA-256 манифеста и архива.
  Release gate проверяет структуру, выборку, размеры и привязку, а не
  сравнивает наблюдения с числовыми лимитами.

Локальное воспроизведение на родной платформе (`BUNDLE` — установленная
версия с соседней квитанцией; `ARCHIVE` и `REPORT` — абсолютные пути):

```sh
python3 scripts/release-resources.py collect "$BUNDLE" "$ARCHIVE" "$REPORT"
RIVECT_RELEASE_ARCHIVE="$ARCHIVE" RIVECT_RELEASE_RESOURCES="$REPORT" \
  sh scripts/release-gate.sh --bundle "$BUNDLE"
```

Локальный отчёт с `null` в полях GitHub commit/run не подходит для CI.
Для проверки только структуры и привязки без повторных замеров используйте
`verify` вместо `collect`.

## Исторический корпус v1 (заморожен)

Ниже декларация и результаты трёхфайлового v1. Они не доказывают
приёмку v2 и не требуют повторного прогона.

Every number and workload below is declared **before** the candidate is
measured. The fenced declaration is the frozen artifact: the release report
carries its SHA-256 digest, and a later change to the corpus, the repeats, the
percentile rule or any limit is a new declaration rather than a correction of
the measurement it already produced. A threshold chosen after seeing the
result is not evidence; it is a post-hoc fit.

The offline AC-003 corpus runs against the exact installed candidate: the
packaged bundle produced by `scripts/package-release.sh` (the executable, the
confined helper beside it and `rivect.manifest.json`). The checkout's test
harness drives the bundle; no provider request and no platform outside the
declared conditions is involved. Real provider-cache trials (AC-058) and the
provider legs of AC-048 stay `NOT_RUN` with the exact missing prerequisite
recorded below — their absence never becomes a PASS and never blocks the
offline corpus, whose own legs are mandatory.

## Frozen declaration

```toml
schema_version = 1
frozen_on = "2026-11-09"

corpus = ["startup", "input", "cancel", "search", "index", "long-session", "install"]
candidate_repeats = 100
p99_min_samples = 100
long_session_turns = 64
percentile = "nearest-rank: rank = ceil(p/100 * n), 1-based, clamped to n"
baseline = "empty data root, release candidate from scripts/package-release.sh, warm cargo target directory"
conditions = "linux with /proc and 100 Hz USER_HZ; one sample is one fresh installed process run; CPU and RSS are sampled every 1 ms across the owned process group"
platform = "linux"

[limits.startup]
p50_ms = 500
p95_ms = 1500
p99_ms = 3000

[limits.input]
p50_ms = 1500
p95_ms = 3000
p99_ms = 5000

[limits.cancel]
p50_ms = 1500
p95_ms = 3000
p99_ms = 5000

[limits.search]
p50_ms = 1500
p95_ms = 3000
p99_ms = 5000

[limits.index]
p50_ms = 5000
p95_ms = 10000
p99_ms = 20000

[limits.long-session]
p50_ms = 5000
p95_ms = 10000
p99_ms = 20000

[limits.install]
p50_ms = 20000
p95_ms = 60000
p99_ms = 120000

[owned]
cpu_ms = 600000
rss_bytes = 2147483648

[kit]
disk_bytes = 67108864
package_bytes = 67108864
package_files = 3
install_ms = 120000

[not_run]
provider_cache = "AC-058 provider-cache trials need a frozen cold/warm cohort measured against an approved provider account; this offline run holds no provider grant"
provider_legs = "AC-048 provider legs need a matched provider trial through the same approved account; only the offline accounting is proved here"
```

## The corpus workloads

One sample is one fresh run of the installed bundle. The corpus is fixed here,
before measurement:

| Leg | Workload | What one sample measures |
| --- | --- | --- |
| `startup` | `rivect --version` from the bundle | process start to answered version |
| `input` | `rivect settings --data-root <root>` | one-shot runtime open, session attach and settings answer |
| `cancel` | `rivect --headless`: `session.attach`, `task.submit` create, `task.submit` cancel | task creation and the cancellation path |
| `search` | `rivect --headless`: `session.attach`, one created task, `command.execute session.search` | the recorded-session search path |
| `index` | `rivect --headless`: `session.attach`, `command.execute project.init` over a small project | the index generation cut |
| `long-session` | `rivect --headless`: `session.attach`, then 64 `runtime.status` dispatches | a long-lived session's repeated turns |
| `install` | `sh scripts/package-release.sh <fresh destination>` | build-install and packaging |

`candidate_repeats` is the sample count per leg. A percentile is reported only
when the leg holds at least the frozen `candidate_repeats` sample count; a leg
with fewer eligible samples reports no p99 and the release verdict is not
PASS. Every percentile is the frozen nearest-rank figure, so it is the same
arithmetic for every leg and every run.

## All-owned processes, disk and package

CPU is the sum of each owned process's consumed user+system time; RSS is the
largest summed resident set observed for one owned group across the corpus.
The group is the installed process and every descendant it starts (the index
worker included), and each pid is counted once. A sample that exits before the
millisecond sampler reads it contributes no observation; the corpus requires
an observed group before it can be measured, and an unmeasured group never
counts as under budget.

The kit counters are the installed bundle's bytes plus the data root one
ordinary run creates, the packaged artifact payload's bytes and file count, and
the build-install wall time of one fresh packaging run. The installed
candidate's build identity and the SHA-256 of its manifest bind the report to
those exact bytes.

## The verdict

A measured leg over a mandatory limit **blocks the release**: the verdict is
`blocked`, never a PASS with a warning. A missing corpus leg, an ineligible
p99, or a platform that cannot supply the declared measurements is `not
PASS`. `NOT_RUN` is reserved for the two provider rows above; each carries
its exact missing prerequisite, and any other `NOT_RUN` row keeps the
verdict at not PASS. The report prints the frozen declaration's digest, the
candidate identity and digest, the baseline and the conditions beside every
measured figure, so the release claim can be re-derived from the evidence
without re-reading this file's prose.

The frozen declaration's digest is recorded in the release measurement test;
it is the pre-declaration anchor, not a value derived from the run.

## Measured baseline addendum (2026-11-10, record only)

`/rite-review` found that the frozen declaration above carried no recorded
baseline artifact. This addendum records the measured baseline the candidate
produced; it is **not** a new declaration, the frozen block above is unchanged,
and its digest remains the pre-declaration anchor. The numbers below were
observed after the declaration, so they are evidence about this candidate, not
the fit that chose the limits.

Run: `cargo test --locked --test measurement -- --nocapture` on the reviewed
candidate (7 legs × 100 samples, linux, the declared conditions):

| Figure | Observed | Frozen limit |
| --- | --- | --- |
| startup p95 | 6.14 ms | 1500 ms |
| input p95 | 12.80 ms | 1500 ms |
| cancel p95 | 13.23 ms | 1500 ms |
| install p95 (install leg) | 156.94 ms | 120000 ms |
| owned RSS peak | 93.1 MiB | 2 GiB |
| kit disk | 28.0 MiB | 64 MiB |

Derivation of the limits: each limit was set at least an order of magnitude
above the observed pre-declaration figures from the parent measurement
(position 18) and the same corpus workloads described above, so a limit can
detect a regression without encoding a machine-specific exact number. The
limits were frozen before this candidate's run; the observed figures stay far
below them and are recorded here as the baseline artifact REQ-003 asks for.

