# ADR-0001: единый Rust-комплект Rivect

Status: ACCEPTED (делегированный технический выбор; не одобрение Build).
Date: 2026-09-08.
Sources: master §§2/4.1–4.4/8.2/10.14/17; DEC-003; [исследование](../../research/stack-selection.md), [методика](../../research/performance-budgets.md).

## Контекст

Нового продукта ещё нет. Требуются один событийный Harness Core, TUI/headless, native search/AST/LSP/graph, durable state, управляемые эффекты и проверяемая поставка macOS/Linux. Нельзя требовать другой coding CLI или сравнивать прототипы Rivect на разных языках. Конкретный стек пользователь делегировал разработчику.

## Варианты

| Вариант | Сильная сторона | Цена в заданном продукте |
| --- | --- | --- |
| Rust + Tokio + Ratatui/Crossterm + bundled SQLite + native search libraries | Search/AST engines и собственный runtime используют один язык/API; comment-preserving TOML editor; per-target native release | C build SQLite/grammars в CI, более сложный compile graph, OS-specific isolation, реальные resource budgets ещё не измерены |
| Go + Bubble Tea + SQLite + packaged search helpers/cgo | Небольшой application toolchain, stdlib network/process/concurrency | Для выбранных AST/text engines появляются helper/cgo seams; comment-preserving config требует отдельного решения; нельзя обещать pure-Go комплект после выбора cgo |
| TypeScript + Node/Bun + Ink + native/WASM engines | Развитые provider/MCP/LSP экосистемы, удобное composition | Runtime и native-addon/prebuild/ABI матрица, packaging compiled assets; совместная latency и installed path не подтверждены |

## Решение

Выбран Rust 1.98.1, один Cargo package с библиотекой и executable `rivect`; модули по владельцам поведения, без service-per-capability. Точные версии и лицензии выбранных libraries находятся только в реестре research/stack-selection.md. Tokio — I/O runtime; Ratatui/Crossterm — TUI; reqwest — HTTP; rusqlite с bundled SQLite — durable storage; grep/ignore/globset и ast-grep-core/Tree-sitter — native search. LSP и произвольные программы остаются управляемыми процессами по реальной необходимости.

Config — TOML с toml_edit и одним registry/schema resolver. Credentials — explicit native stores через keyring-core, не универсальный wrapper с неявным выбором fallback. Ни собственная криптография, ни state-machine framework, ни второй graph server, ни self_update как orchestration не вводятся.

Binds: разработку одной production-кодовой базы и её native dependency graph. Prevents: multi-stack prototypes, обязательный внешний coding CLI, невидимый runtime/prebuild install у пользователя, второй planner/scheduler ради библиотеки.

## Последствия и admission

Rust не объявляется самым быстрым: full-stack сравнительных измерений нет. Решение принято по locality и сложности integration seams. Реальный startup/input/cancel/CPU/RAM/package overhead измеряется после первой настоящей вертикали по frozen методике. macOS/Linux support подтверждается по каждой заявленной связке, не по наличию crate.

До первой сборки закрепить compiler и Cargo.lock, проверить совместные dependency versions/features и исполняемые build scripts, сохранить licences/SBOM. До продуктового поведения проверить восемь config fixtures настоящим Rust parser/schema; выполненная плановая tomllib/Pydantic проверка не заменяет её. SQLite проверяется по actual runtime version и FTS5, не compile-time minimum bindings. Backend без требуемой изоляции не выполняет эффект с ambient правами.

Build не разрешён этим ADR: требуется готовый инженерный план, /rite-vet и human Plan approved. Login, платные испытания, миграция живых данных, публикация и новая data destination требуют своих допусков.

## Пересмотр

Только подтверждённое несовместимое с обязательным контрактом ограничение выбранного комплекта открывает адресный пересмотр ADR. Сохранить evidence, непокрытый REQ и стоимость альтернативы; не начинать автоматически перепись или серию сравнительных прототипов. Временная недоступность аккаунта/платформы не является доказанным дефектом языка.
