# CI/CD Rivect

## Решение

2026-11-16. Исходный кандидат: `c02f551b64ca061b78eac02184bc8d4d731e9c8c`.
Область: GitHub Actions, скрипты evidence и test-only потребление готового bundle.
Функциональные и защитные требования release conjunction не меняются.
Исследование 22 первоисточников хранится локально в `research/ci-cd-design.md`,
в Git не включается. Принятое решение: [ADR-0005](adr/0005-ci-artifact-promotion.md).

Критерий: каждый Cargo target исполняется одним владельцем на платформу в одном
workflow run; package/publisher не повторяют suite. Все release-проверки относятся
к неизменным байтам готового native bundle. Ошибка producer, отсутствующий receipt
или несовпадающий hash не превращаются в готовый релиз.

```mermaid
flowchart LR
  Q[quality: fmt/clippy/docs/deny/scripts] --> V[verify-release: conjunction]
  T[test: Linux + macOS] --> V
  V --> P[publish: один владелец Release]
```

`quality` и `test` выполняются для PR, main, tag и ручного запуска. Последние два
узла — только для `v*` tag. PR не получает write token или production secrets.
Tag должен совпадать с Cargo version. Поддерживаемые native targets:
`x86_64-unknown-linux-gnu` на Ubuntu 24.04 и `aarch64-apple-darwin` на macOS 15.
Runner labels закреплены; конкретный образ VM продолжает обновляться GitHub.

## Установка опубликованного релиза

```sh
curl -fsSL https://github.com/ViktorsBaikers/Rivect/releases/latest/download/install.sh | sh
```

Поддерживаются macOS Apple Silicon (`aarch64-apple-darwin`) и Linux x86_64
с glibc (`x86_64-unknown-linux-gnu`, build/runtime baseline Ubuntu 24.04).
Intel macOS, Linux ARM64 и musl этой поставкой не поддерживаются.
Установщик принимает только пятифайловый OpenTUI-пакет v2. Нужны Python 3
и GitHub CLI с `gh attestation verify`: установщик проверяет подпись архива,
workflow и исходный тег при установке и откате. Cargo и jq не нужны.
Опубликованные и установленные пакеты v1 остаются нетронутыми. Новый
установщик не выбирает v1 даже для отката: цель отката — только ранее
активированный и повторно проверенный v2. Подробности — в [контракте установки](installed-release.md).
Workflow не меняет настройки репозитория и не переносит существующие теги.
Имя архива — `rivect-TAG-TARGET.tar.gz`, checksums — `TARGET.sha256`.
До переключения активного bundle установщик проверяет запуск CLI через
`--version`; несовместимый бинарник не заменяет работающую установку.
Установка без `sudo`: полные bundles хранятся в
`~/.local/share/rivect/releases/ARCHIVE_SHA256/`, атомарный symlink
`~/.local/share/rivect/bin` выбирает активный bundle. Установщик однократно
добавляет этот bin в PATH через профиль shell: `${ZDOTDIR:-$HOME}/.zshrc`
для zsh, `~/.bashrc` и login profile для bash, `~/.profile` для sh/неизвестного
shell, `~/.config/fish/config.fish` для fish. Pipe не меняет PATH родительского
shell: после установки нужно открыть новый терминал или перечитать профиль.


Ubuntu 24.04 сохраняется как build/runtime baseline: переход на новый runner ради
`setpriv` поднял бы glibc baseline архивов. `ci-linux-prerequisites.sh` собирает
только `setpriv` util-linux 2.41.5 из upstream tarball с закреплённым SHA-256 и
устанавливает его в `/usr/bin/setpriv` disposable VM; системные библиотеки и
production bundle не меняются. Источник и checksum проверены 2026-11-16:
[upstream checksums](https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/v2.41/sha256sums.asc).
Лицензия utility — GPL-2.0-or-later; utility не включается в поставку Rivect.

### macOS: настоящий Git и Exec-only scope

macOS jobs `test` и `verify-release` находят настоящий Apple Git через
`/usr/bin/xcrun --find git`. Приватный каталог `mktemp` под `$RUNNER_TEMP`
содержит только symlink `git` на этот executable и добавляется в `GITHUB_PATH`.
Это исключает зависимость confined carrier от Homebrew dylibs вне профиля;
весь `/usr/bin` не поднимается в PATH, поэтому выбор Python не меняется.

По §15.1 ТЗ право исполнения не даёт права читать постороннюю конфигурацию.
Production macOS launcher после очистки окружения задаёт фиксированный
`GIT_CONFIG_NOSYSTEM=1`, а не наследует значение вызывающего процесса:
скопированный Apple Git не должен читать системный `gitconfig` из Xcode.
Seatbelt profile, файловые разрешения и классификация ошибок не расширяются.
AC-078 / DEC-022 по-прежнему проверяется настоящим Git, скопированным в scope;
отдельный `true` control, `/dev/null`, отрицательные проверки и лимиты сохранены.
Недоступная sandbox остаётся `NOT_RUN`; отказ после успешного control — failure.

## Владельцы проверок

| Проверка | Владелец | Исключение повтора |
| --- | --- | --- |
| fmt, clippy, rustdoc, cargo-deny, workflow/shell contracts, offline installer tests | quality | Не выполняются в publisher |
| lib/bin/examples и все integration targets workspace | `scripts/ci-test.py` | Перечень из `cargo metadata`; один вызов на target |
| process-heavy helper | тот же runner | Первый пакет, один test thread |
| обычные targets | тот же runner | Два test threads; не автоматические retries |
| doctests | отдельный step test | Явный target selection выше их не включает |
| provider/acceptance/search evidence | `offline-evidence.sh --logs-dir` | Проверяет один сохранённый execution вместо повторного Cargo |
| installed ordinary и UI matrix | их integration targets | Receipts пишутся при первом прогоне, не запускаются повторно gate |
| platform-exclusive legs | `xhost-serve.sh` | Читает PASS + hash-bound execution + отсутствие NOT_RUN; тесты не запускает |
| final conjunction | `release-gate.sh --receipts-only` | Остальные negative tests этого target уже прошли; exact conjunction отложен |
| release mutation | publish | Один job для обеих платформ, без checkout/Cargo/кандидатных executables |

Повтор на другой ОС — проверка другого native carrier, не дубль. Main/PR/tag —
независимые события; они могут проверять один source SHA повторно. Между событиями
не введён privileged `workflow_run` или доверие произвольному старому cache.
Дедупликация относится к одному workflow run, а не к произвольной истории сборок.

## Ускорение native CI/CD

Исторический hosted baseline v1, commit `5ae0d85`: [push на main — 44202208504](https://github.com/ViktorsBaikers/Rivect/actions/runs/44202208504), [tag — 44206567912](https://github.com/ViktorsBaikers/Rivect/actions/runs/44206567912). Ниже — фактические времена main, не целевые значения:

| Метрика | Linux | macOS |
| --- | ---: | ---: |
| Native job `test` | 28:26 | 21:03 |
| Шаг Cargo targets и формирования evidence | 23:48 | 18:37 |
| Сумма времени компиляции по логам Cargo | 145 с | 196 с |
| Длительный installed target | `installed`: 602 с | `installed_tui`: 296 с |

Сумма времени компиляции не равна wall time шага. Эти цифры описывают v1 и не подтверждают ускорение v2/OpenTUI на hosted runners.

### Порядок исполнения

- [Native workflow](../.github/workflows/ci.yml) через [platform wrapper](../scripts/ci-platform-test.sh) запускает [`ci-test.py --jobs 2`](../scripts/ci-test.py). Только явно перечисленные независимые provider/search targets могут выполняться попарно; они используют изолированные хранилища, каталоги или loopback fixtures. Helper идёт первым с одним потоком libtest, остальные targets — с двумя потоками libtest на target. Native budget, keyring, PTY и измерительные targets остаются последовательными. Новый Cargo target обнаруживается автоматически через `cargo metadata` и выполняется последовательно, пока его явно не допустят к параллельному запуску. Логи не смешиваются: для каждого target сохраняются полный вывод, exit status, команда, SHA-256 манифеста и вывода, а также `duration_seconds`.
- [`ci-tui-test.py`](../scripts/ci-tui-test.py) находит `tui/*_test.py` и запускает не более двух suites одновременно. Те же шесть suites используют приватный `libexec/rivect-tui`; остальные используют публичный `rivect` из кандидата. Полный вывод каждой suite сохраняется отдельно и печатается в CI вместе с её статусом и временем; при ошибке одной suite остальные завершаются, а шаг возвращает ненулевой статус. TypeScript-проверки, независимая MCP SDK-проверка, нативная установка с upgrade/rollback в PTY и отдельные doctests остаются в workflow.
  Проверки wire и сборка декодера кадров ограничены 10 минутами, отдельный PTY-этап — 5 минутами. Имя suite появляется до запуска, поэтому зависание не скрывает незавершённую проверку.
- `test` и `verify-release` используют общий Cargo cache для каждой платформы (`shared-key: native-v2-…`, `cache-bin: false`). Сохранять кэш может только `push` на `main`; verify только восстанавливает его. Первый прогон с новым ключом холодный до появления совместимой записи. Кэш не заменяет неизменяемый artifact текущего run: архив кандидата и receipts передаются отдельно. У `xhost-*` и `release-*` отключено повторное сжатие внешнего ZIP (`compression-level: 0`), потому что payload уже содержит `.tar.gz`. Exact gates, проверки digest и publisher не меняются. Nextest и xlarge runners не используются.
- Упакованные headless-проверки на Linux используют только адрес выделенной
  D-Bus-сессии от platform wrapper. В обычном офлайн-прогоне не обращаются
  к пользовательскому bus. Нативная проверка Secret Service и пять
  отказов `docs.search` с нулём HTTP-соединений по-прежнему обязательны.
  Для сессии нужны `gnome-keyring` и `dbus-daemon`, без `dbus-x11`
  и рекомендованных desktop-пакетов. [Ubuntu Noble `dbus-run-session`](https://manpages.ubuntu.com/manpages/noble/man1/dbus-run-session.1.html)
  запускает собственный `dbus-daemon`. На чистом Noble x86_64 APT выбирает
  124 пакета вместо 213, а реальный Secret Service возвращает коллекцию
  `login` без `dbus-launch`. Это сравнение dependency plan, не время hosted job.

### Критерий повторного замера

Сравнивать hosted v2 до и после правки на одинаковых входах, с тем же типом события и runner label/image отдельно для Linux и macOS. Сопоставлять cold с cold и warm с warm; по логам различать miss, частичное совпадение ключа и точный hit. Отдельно фиксировать ожидание runner, restore/save, сборку, wall time native шага и jobs, размеры и время передачи артефактов, время от события до последнего успешного gate. Ускорение подтверждается повторяемым снижением wall time при том же inventory проверок, сохранённых diagnostics и неизменных обязательных verdicts/receipts; исторический v1 служит ориентиром, не контрольным прогоном v2.

Локально на одном установленном v2-комплекте macOS arm64: 21 Python suite
прошла и старым последовательным циклом (115 с), и новым runner (61,45 с).
Повтор на заново собранном комплекте (SHA-256 bundle manifest
`1df42eba376f84c0c742d302d2b8444c385c47edb6485e743cc5ed4d2d49c3ee`):
те же 21 suite прошли за 60,30 с; нативная установка и проверка SBOM прошли.
На Ubuntu 24.04 x86_64 монитор выделенного D-Bus подтвердил 0 вызовов
`OpenSession` без адреса и 5 с явным адресом на историческом бинарнике
из run 44202208504. Обе ветки дали пять типизированных отказов без HTTP.
Это проверка маршрута обращения, не замер 602-секундной задержки runner.
Linux-only ветка `tests/installed.rs` также прошла `cargo check --locked`
на `x86_64-unknown-linux-gnu` с Rust 1.98.1. Это проверка компиляции,
не полный native Linux gate.

PTY-проверки сохранены после смены интерфейса: Escape проверяет, что вопрос
остаётся без ответа; вставка сравнивает физические колонки VT100;
идентификаторы задач и скрытые строки проверяются в деталях и расширенном
учёте. На 60×20 оставили предупреждение о заполнении контекста и целую
команду /compact на одной строке.
При прокрутке статус потока остаётся рядом с редактором. Итог в ленте
отличает завершённый вывод от частичного и явно помечает усечение. Метка
занимает строку отступа узла; офлайн-кадр 160×50 сохраняет первую реплику.
Оракулы сверяют состояние ядра и VT100, включая перенос метки на две строки.
PTY fixture сохраняет один VT100-экран при resize и проверяет видимый кадр,
а не строку в последней ANSI-дельте. Loopback peer явно включает blocking
после accept: иначе macOS наследует режим listener и не ждёт deadline чтения.
Матрица `TERM=dumb` проверяет все записанные байты, включая диагностику
Bun. Launcher передаёт `NO_COLOR=1` для `TERM=dumb` и явного `NO_COLOR`,
даже пустого; сообщение об ошибке при этом остаётся видимым.

Первоисточники: [GitHub Actions — dependency caching](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching), [README upload-artifact v7.0.2](https://github.com/actions/upload-artifact/blob/cf430e030ddbb5b0abf93d22962f4752f3646cd9/README.md), [Cargo Book — cargo test](https://doc.rust-lang.org/cargo/commands/cargo-test.html), [Nextest — модель изоляции тестов по процессам](https://nexte.st/docs/design/how-it-works/). Проектные границы promotion: [ADR-0005](adr/0005-ci-artifact-promotion.md).

## Кандидат и evidence

1. `sh scripts/package-release.sh DESTINATION` создаёт только пакет v2 вне
   checkout. Существующий destination отклоняется. Smoke: настоящий
   `rivect --version` и `--help`.
2. Установленные тесты берут `RIVECT_TEST_BUNDLE`, проверяют хэши и
   идентификатор сборки, затем копируют пакет в отдельный каталог.
   Ошибочный override останавливает тест, а не подменяет пакет новой сборкой.
   Пакет v1 не строится. На релизном теге и при ручном preflight
   (`gh workflow run ci.yml --ref main`) обе платформы собирают
   [свежий отчёт AC-003 для v2](release-budgets.md) по своему точному
   архиву и установленному комплекту. Числовых порогов нет. Отсутствующие,
   неполные или относящиеся к другому архиву/run измерения блокируют релиз.
   Обычные push и PR не тратят время на эти замеры. Ручной preflight
   не блокирует очередь обычных push: concurrency group включает тип события.
3. Runner сохраняет полный лог, exit code, фактическую команду, manifest SHA-256 и
   output SHA-256 на target. `--show-output` сохраняет per-test PASS строки и
   успешные markers без nocapture-interleaving. Failed targets сохраняют логи,
   но не создают family receipts. Новый target автоматически попадает в inventory.
4. Producer проверяет digest/status/candidate, обязательные oracle PASS и markers.
   Несколько manifests потребляют один execution. Логи и receipts не входят в
   compilation cache.
5. Native bundle переносится как tar.gz: ZIP artifact не должен потерять executable
   mode. Receipts связывают source SHA, run ID, platform и manifest digest native
   кандидата. Cross-host bind требует обе платформы и точный allowlist legs,
   проверяет inventory и binary hashes обоих архивов **до распаковки executable**.
6. В preflight и на релизном теге verify восстанавливает receipts,
   применяет cross-host fold и запускает exact conjunction. Он сверяет отчёт AC-003 с
   кандидатом и переносит его SHA-256 в verdict. Архив копируется из test artifact
   побайтно: нет повторной production-сборки или перепаковки.
   Корневой `install.sh` копируется в отдельный `install-TARGET.sh` для каждой
   платформы; SHA-256 этих байтов включается в её verdict как `installer_sha256`.
7. Только при push релизного тега publisher требует обе платформы, валидные verdicts
   и совпадающие SHA-256 архивов, отчётов AC-003 и скрипта установки. Он
   проверяет побайтное равенство двух копий установщика и публикует один
   `install.sh`, его checksum и по одному `*.resources.json` на платформу.
   Скачанный код в job с write token не исполняется.
   Тег проверяется до создания draft и повторно после загрузки assets,
   непосредственно перед публикацией. Только общий ready публикует draft.
   GitHub Actions аттестует архивы обеих платформ независимо от настройки
   immutable releases. Non-ready по-прежнему сохраняется как диагностический draft.
   Upload failure не выставляет частичный stable.

Exit 0 — ready и ноль retained legs; exit 5 — честно вычисленный non-ready,
остаётся общим draft/prerelease с verdict JSON. Допустимы только conjunction exits
0 и 101 (libtest assertion failure). Остальные exits, включая 137/143, отсутствие
или невалидный verdict и failed conjunction при ready=true — failure, не draft-успех.
Существующий Release не перезаписывается: повтор после частичной публикации требует
проверки уже существующих assets, а не `--clobber` или движения тега.

## Безопасность и воспроизводимость

- Actions закреплены полным owning commit SHA; first-party runtime Node24.
- Checkout не сохраняет credentials. Только publisher получает `contents: write`;
  у него нет checkout, Cargo, cache или запуска скачанного кода.
- Download ограничен текущим workflow run; digest mismatch — error. Проверяется
  полнота ожидаемых файлов, а не только успех wildcard download.
- Cache — только ускоритель зависимостей; запись только на `push` в `main`.
- Rust/components берутся из `rust-toolchain.toml`; lockfile не обновляется CI.
- Linux namespace prerequisite задан каждому job, который реально исполняет
  sandbox. Раньше его отсутствие ломало package с errno 13.
- Secret Service — локальный disposable D-Bus session и тестовый namespace;
  production OAuth/LLM/API не вызываются. macOS использует тестовый keychain namespace.
- Job timeouts и `fail-fast: false` ограничивают ожидание, сохраняя результат каждой
  платформы. Устаревший PR отменяется; release не прерывается новым PR.
- `actionlint` закреплён на v1.7.12; shellcheck и Python stdlib проверяют скрипты.
  SHA pins не делают транзитивные downloads/OS images полностью immutable.

## Известные границы

Три существующих repository-policy tests требуют не поставляемые в source checkout
agent/ADR/research inputs. Runner пропускает их **только при отсутствии prerequisites**
и записывает точные имена `NOT_RUN` в `target/ci-logs/not-run.json`.
Пять Linux `/proc`-oracles `index_worker` остаются в Linux leg, не исполняются на macOS.
Exact conjunction отмечен как отложенный в test job и исполняется tag verify job.
Это не утверждение, что весь локальный §14 gate прошёл на clean GitHub checkout.
Локальный §14-набор остаётся обязательным и не ослаблен.

Автоматическая настройка branch protection, required-check names, immutable tags,
protected release environments, signing и credentials не выполняется этим diff.
Проверка тега и undraft — отдельные API calls, не атомарная операция; запрет движения
релизных тегов должен обеспечиваться repository ruleset.
При включённых required checks оператор должен заменить старые `gate-linux` и
`test-macos` на `quality`, `test-linux`, `test-macos`; имена зависят от реальных
repository rulesets. Не двигать существующий `v0.1.0`: изменённый workflow требует
нового явно разрешённого push/tag. `--preapprove` не меняет правила хоста для Git.

## Проверка изменения

- `python3 scripts/ci-contract-tests.py`: реальные subprocess/fs проверки dedup,
  failed/stale/tampered evidence, cross-host binding и gate exit semantics.
  Отдельно — 17 сценариев publisher, включая подмену installer и блокировку
  stable при выключенной, недоступной или изменившейся политике immutability.
- `python3 scripts/ci-tui-contract-tests.py`: обнаружение и маршрутизация
  suites, предел двух процессов, целостность логов и неуспешный статус шага.
- `python3 scripts/install-contract-tests.py`: offline installer contracts.
- `actionlint .github/workflows/ci.yml`; `sh -n install.sh`;
  `shellcheck install.sh scripts/*.sh`.
- Полный локальный §14-набор и authentic supplied-bundle regressions.
- Remote CI/publication не считаются проверенными по локальным mocks. Конкретный
  результат запуска и оставшиеся ограничения записываются в отчёте исполнения.

### Проверка переключения на единственный формат v2

- macOS arm64, SHA-256 манифеста `32479d34f2ac3b3d7ffc7fe9de33db93b6fdc3e8784e5e5f8fc9baf80b32fc8c`: SBOM, установка и откат с живой сессией, 21 OpenTUI-набор и 9 Bun-тестов прошли. Источник архива и аттестация в installer-тестах — локальные fixtures.
- Установщик отклоняет v1 до выполнения его бинарника. Проверены пустой HOME, сохранение активного v2 и отказ отката на v1 с существующей записью активации. Установка v2 не меняет файлы прежнего пакета.
- На Ubuntu x86_64 прошли четыре сценария установщика с fixtures: выбор Linux-архива, отказ v1, откат v2 и отказ без подтверждённой аттестации. Это не нативная приёмка релизного комплекта или hosted CI.
- Linux x86_64: образ Rust 1.98.1 и Bun 1.4.4 собрали пакет `20ac1bcc861a4a14a9d2073eb76bbf75dc5e622e1155a380d81c1899611d85f3`; SBOM и публичный `--version` прошли. Нативный тест установщика не прошёл под Rosetta: `probe-write` завершился сигналом (`exit 133`, `mmap_anonymous_rw mmap failed`), так же как helper исторического пакета. Оба не создали файл; это не доказательство правильного sandbox-отказа. Установщик не активировал пакет, sandbox не ослабляли. Hosted Linux — NOT_RUN.
- macOS workspace: 3797 PASS, 1 FAIL, 87 ignored; `release` — 19 PASS. PTY-оракул подсказки после resize разбивал логический текст вместо чтения физических строк сетки. После исправления оракула тот же сценарий на том же v2 — PASS; весь workspace повторно не запускался.
- [Первый hosted run](https://github.com/ViktorsBaikers/Rivect/actions/runs/44500363083) остановился до нативной приёмки: Linux-тест брал basename из `ps comm`, macOS-тест искал цельную строку в частичной перерисовке, ShellCheck отвергал `test -ef` в POSIX `sh`. Локально после правок: Linux x86_64 (эмуляция) и macOS arm64 проверили путь реально запущенного клиента, macOS PTY прошёл сценарий мыши и вставки; пять сценариев очистки проверили принадлежность sidecar по inode.
- [Второй hosted run](https://github.com/ViktorsBaikers/Rivect/actions/runs/44503452045): quality, Linux-проверка пути клиента и macOS-проверка мыши прошли. `decision_test.py` на Linux не увидел witness, на macOS остался единственным незавершённым набором. На Linux arm64 со штатным sandbox воспроизведена отдельная гонка выхода: generic VT-кадр не подтверждал возврат управления после witness. После ожидания `blocked` вместо generic кадра весь сценарий прошёл на локальных macOS arm64 и Linux arm64.
- На [следующем hosted Linux](https://github.com/ViktorsBaikers/Rivect/actions/runs/44507335084) повторился ранний отказ witness. В тестовом hook воспроизведён `EPIPE`: старый `cat` мог закрыть stdin до записи запроса. Fixture теперь читает запрос перед ответом. Контроль с задержанной записью и весь `decision_test.py` прошли локально на macOS и нативном Linux arm64.

### Локальный результат оптимизации v2

- Финальный пакет (префикс SHA-256 манифеста `b99111fe62227`):
  21 OpenTUI suite, SBOM и кадры четырёх размеров прошли.
- Полный macOS workspace: 3798 PASS, 1 FAIL, 87 ignored. Последний отказ
  был в PTY-оракуле. После исправлений только тестовых fixtures повторены
  обе затронутые цели на том же пакете: `effect_boundary` — 83 PASS,
  `mcp` — 52 PASS, 1 ignored. Workspace Clippy и rustfmt прошли; цельный
  workspace после правки fixtures и новый hosted run не повторялись.

### Локальный результат 2026-11-16

- PASS: 11 Python contract tests, `actionlint`, `shellcheck`; 17 native release tests
  с supplied candidate; настоящий CLI `--version`/`--help`.
- Финальный локальный §14-набор: все семь команд завершились exit 0;
  `cargo test --workspace` — 3776 passed, 68 suites, 85 ignored;
  doctests — 43 passed. Логи: `/tmp/rivect-ci-final.YoVkvd/gate-{0..6}.log`.
- Прежний MCP timeout (`duplicate_input_required_reuses_one_operation_p4`)
  сохранён в `/tmp/rivect-ci-proof.ZeVo5e/gate-3.log`. В финальном полном
  прогоне тест прошёл; причина прежнего сбоя не установлена, исправление
  MCP не заявляется.
- Cold Linux proof выявил необходимый debug-helper prebuild; runner исправлен,
  существующий contract test прошёл RED→GREEN. Два test-only measurement seams
  исправлены без изменения production timeout или порогов: native procfs retirement
  после join и измерение CloudCode send отдельно от SQLite/settlement.
- Native macOS runner прошёл. Финальный Linux runner: 64 команды, все exit 0;
  3774 passed, 89 ignored; затем doctests. Cold debug-helper prebuild проверен.
  Все семь corpus legs по 100 samples прошли неизменные frozen limits.
- Corpus исполнялся после fresh candidate build, как в workflow: release cache
  соответствует source. Owned RSS — 92401664 bytes при лимите 2147483648;
  прежний cold-rebuild sample не считается warm-baseline результатом.
- Consumer-only promotion проверен на обоих подлинных archives без producer reruns:
  Linux gate exit 0, retained legs 0; macOS exit 5, retained leg `ingress.exec`
  из-за local Homebrew Git/pcre2 вне sandbox. Sandbox не ослаблен.
- Proof carriers: Linux arm64 Docker и native macOS arm64, не hosted
  Ubuntu x86_64/macOS-15. Итоговые команды, manifests и логи: EVID-20-95.
- Независимое correctness review: подтверждённых дефектов нет. Два security findings
  закрыты кодом и regression proof: повторная tag check; abnormal-exit rejection.
- Push `9b2ce35` выполнен. Первый hosted run
  [43930457186](https://github.com/ViktorsBaikers/Rivect/actions/runs/43930457186)
  завершился FAIL: ShellCheck SC2015, Linux `setpriv` без Landlock options,
  macOS `index_worker` и `search_index`. Package artifacts не созданы; сохранены
  diagnostics обеих платформ. Tag/publication не запускались.
- Исправления среды после hosted FAIL: ShellCheck clauses переписаны как `if`;
  util-linux 2.41.5 собран на настоящем Ubuntu 24.04 container, Landlock
  in-scope write прошёл, outside write получил Permission denied. 11 Python
  contracts, actionlint и Ubuntu 24.04 ShellCheck прошли. Это не hosted GREEN.
- macOS memory cause пока не установлена: локальный bounded probe на Darwin 27
  не воспроизвёл поведение macOS 15; hosted stderr и peak footprint отсутствуют.
  Классификация ошибок и memory limits не ослаблялись.
- Watcher repair подавляет membership invalidation только для собственного runtime.
  Для name-only exclusions `target`, `node_modules`, `.git` membership flag сохранён:
  эти имена не доказывают исключение файла из настоящего enumeration policy.
  Regression проверяет automatic create/delete repair в `src` и unignored
  `node_modules`, полный snapshot oracle и stale предыдущего generation.
  Предшествующие RPC errors входят в narrowing failure diagnostics; исходная
  причина hosted narrowing FAIL ещё не доказана.
- Diagnostic follow-up: raw native peak accessor сохраняет ABI296/offset240;
  отдельное synthetic воспроизведение запускается только после исходного memory
  failure. Custody сохраняется до final sample, stderr bounded/sanitized,
  сомнительные наблюдения остаются inconclusive. Контрольный настоящий child
  проверяет exit23, zombie sample, reap и stderr cap; исходные assertions не менялись.
- Полный локальный §14 после коррекций PASS: 3778 tests, 68 suites, 85 ignored;
  43 doctests; fmt/clippy/rustdoc/deny/locked fetch прошли. Fresh bundle и
  настоящий CLI smoke прошли. Логи: `/tmp/rivect-diag-final.vr0Kf7/`,
  `/tmp/rivect-ci-diagnostic-final-clippy.log`. `index_worker`: 49 passed,
  2 ignored. PID marker fixture публикуется атомарно после полной записи.
- Независимые scoped spec/code reviews: actionable membership-loss finding
  исправлен с реальным create/delete proof; owning recheck — no-findings.
- Push `800fa3f` выполнен. Hosted run
  [43962787351](https://github.com/ViktorsBaikers/Rivect/actions/runs/43962787351):
  quality и Linux PASS; macOS FAIL в `auth_band7` и `index_worker`.
  `search_index` прошёл. Это не общий CI GREEN.
- Linux package создан: artifact `xhost-linux` (14276901595). Скачанный archive
  содержит только `rivect`, `rivect-sandbox-helper`, `rivect.manifest.json`;
  hashes бинарников, executable modes и привязка receipt к commit/run проверены.
  SHA-256 manifest:
  `5a733d9281e206e470ccc4d56596e436a6e493b79645243b79b37f6a3d03e8c4`.
  Linux ELF на macOS не запускался. macOS package пока не создан.
- Hosted synthetic memory probes завершились ENOMEM/SIGABRT при peak ниже
  512 MiB; пересечение physical limit не доказано. Parser может законно первым
  получить process resource limit. Следующая коррекция сохраняет оба budget
  guards: physical fixture использует уникальные paced blocks; parser принимает
  объявленные memory/resource-limit outcomes с прежним deadline.
  Промежуточный `index_worker`: 49 passed, 2 ignored; fmt/clippy PASS.
  Review выявил недостаточный oracle: обычный SIGABRT тоже классифицируется
  как resource limit. Принимаемому сигналу нужна атрибуция из исходного запуска;
  отдельное synthetic воспроизведение её не заменяет. Исходный stderr теперь
  захватывается bounded exec-wrapper без смены PID, stdin, arguments или memory
  limits. Resource signal принимается только с каноническим Tree-sitter
  allocation/reallocation refusal. Настоящий посторонний SIGABRT отвергается;
  восемь positive calibrations проверяют classifier, не изображая OS observations.
  Финальный локальный `index_worker`: 50 passed, 2 ignored; fmt/clippy PASS.
  Логи: `/tmp/rivect-macos-attribution-native.log`,
  `/tmp/rivect-macos-attribution-clippy.log`. Scoped recheck: no-findings.
- Hosted polling guard наблюдал один poll при общей 400 ms квоте. Начальная
  HTTP работа тоже расходует квоту; фиксированный минимум polls не является
  переносимым oracle. Детерминированная замена прошла 8 unit и 28 integration
  tests: shared budget включает 300 s setup из 400 s; интервалы 20/40 s дают
  ровно 4/2 polls, истечение в 400 s и отсутствие публикации. Прежний отдельный
  publication-admission guard сохранён внутри owner test. Новый hosted proof NOT_RUN.
  Tag/Release не создавались; CI artifacts хранятся семь дней.
- Финальный локальный §14 (2026-11-17 UTC) PASS: workspace tests, отдельные
  doctests, fmt, clippy со всеми targets/features, rustdoc `-Dwarnings`,
  dependency policy и locked fetch. Inputs и полные логи:
  `/tmp/rivect-macos-final.dT1oyW/`; fmt/clippy и targeted memory log указаны выше.
  Настоящий CLI `--version`/`--help` прошёл с очищенным окружением и отдельным HOME.
  Это proof локального кандидата поверх `800fa3f`, не hosted GREEN нового commit.
- Push `be0d5e1` выполнен. Hosted run
  [43998350590](https://github.com/ViktorsBaikers/Rivect/actions/runs/43998350590)
  завершился FAIL: quality PASS; Linux остановился до сборки на `curl` exit 35
  (`Recv failure: Connection reset by peer`); macOS — только physical-memory
  fixture в `worker_failure_classification_is_typed_per_seam`.
  Auth и исправленный parser oracle прошли; исходный parser stderr:
  `tree-sitter failed to allocate 81920 bytes`, `ResourceLimit { signal: 6 }`.
  Это настоящий исходный запуск, не synthetic reproduction.
- Тот же pinned util-linux archive скачан локально с ожидаемым SHA-256.
  Это подтверждает содержимое источника, не исправность сети GitHub runner.
  Network bootstrap code не менялся. Physical fixture требует отдельного
  parent-observer proof без гонки с child address-space guard; коррекция в работе.
- Physical fixture теперь изолирует настоящий parent RSS observer: test-only
  pass-through launcher явно не применяет и не аттестует native AS/DATA caps.
  Конечный writable load — budget + 64 MiB; ожидается строго
  `MemoryExceeded`/`BudgetExhausted`. Budget − 128 MiB control доказывает полную
  readiness и проходит настоящий footprint check перед контролируемой отменой.
  Нет unbounded allocation, pacing, увеличения budget или deadline.
  Genuine-helper parser proof и все остальные classifier seams сохранены.
- Локальный target: 50 passed, 2 ignored; over — `MemoryExceeded`, under —
  `Cancelled`, readiness true. Fmt/clippy PASS; independent frozen-source
  recheck — no-findings. Логи `/tmp/rivect-parent-footprint-{native,clippy}.log`.
  Полный повторный workspace gate выполняется; hosted proof этой коррекции NOT_RUN.
- Повторный полный §14 поверх `be0d5e1` PASS (2026-11-17 UTC):
  workspace tests, отдельные doctests, fmt, all-target/all-feature clippy,
  rustdoc `-Dwarnings`, dependency policy, locked fetch. Source inputs и логи:
  `/tmp/rivect-parent-final.mkRGF0/`. Код production не изменялся.
- Push `e065a6f` выполнен. Run
  [44039494430](https://github.com/ViktorsBaikers/Rivect/actions/runs/44039494430):
  quality и macOS PASS; macOS package `xhost-macos` создан (artifact 14309562457).
  Это первый hosted PASS изолированного physical-observer proof.
  Общий CI всё ещё FAIL: Linux дошёл до candidate build, затем runner отказал
  на существующем пустом `target/ci-logs` (`FileExistsError`), до запуска targets.
- Runner теперь допускает только пустую directory shell, но отвергает symlink
  или любые прежние evidence entries. Exclusive `invocation.log` резервирует
  единственного владельца до Cargo. Нет удаления старых данных или повторного
  исполнения targets. Реальный runner CLI regression прошёл RED→GREEN:
  13 Python contracts PASS, включая неизменность evidence при replay и
  отсутствие записи через symlink. Логи `/tmp/rivect-ci-empty-logs-{red,green}.log`.
- macOS artifact 14309562457 для `e065a6f` скачан и проверен: ZIP SHA-256
  `29261cddec0a001d301fa6e5d055f57c600eb1088354fde4dd510f42f0c170b5`;
  manifest SHA-256
  `e46e100f399f32bc2e3a871f1058f3731673b86da201e3a4b4717f15f131468f`.
  Receipt привязан к commit/run/platform и `auth.keychain`; archive содержит
  ровно три regular files, binary digests и executable permissions совпали.
  Это частичный package proof: Linux artifact этого run отсутствует,
  общий CI не GREEN. Binaries локально не запускались.
- Финальный набор содержит 15 contract tests: дополнительно проверены stale logs
  без owner marker и два конкурентных runner до первого Cargo target.
  Реальная CLI-проверка с ограниченным loopback-gate подтверждает единственного
  владельца; исходный runner при этом не менялся. PASS: 15 tests, 23.882 s,
  `/tmp/rivect-ci-freshness-final.log`. Rust inputs совпадают с §14 proof
  `/tmp/rivect-parent-final.mkRGF0/`; нового Rust-прогона для Python-only diff нет.
- `devrites-engine check dup --worktree`: exit 2, scan incomplete — просканирован
  161 файл; один eligible file недоступен или превышает лимит. Единственный
  показанный cluster — headers/imports и объявления SHA-256 helpers.
  Общий helper не добавлялся: test oracle остаётся независимым. Это не PASS
  проверки дубликатов; ограничение сохранено явно.
