# ADR-0002: типизированные английские ошибки и chrome

Status: ACCEPTED (техническая делегация DEC-003; пользователь 2026-09-10 поручил унификацию и English source strings).
Date: 2026-09-10.
Sources: [C-GOOD-ERR](https://rust-lang.github.io/api-guidelines/interoperability.html#c-good-err); [thiserror 2.0.20](https://docs.rs/thiserror/latest/thiserror/); [research/error-handling.md](../../research/error-handling.md); [research/copy-and-i18n.md](../../research/copy-and-i18n.md); architecture `Error` / `ErrorCode`; `.devrites/principles.md` P-001.

## Контекст

В коде смешаны русские литералы, ad-hoc `"message".to_string()` и owner-enum с `String` payload. Публичный контракт уже требует enumerated `code` и bounded message. Нужно одно правило для всех будущих slices, без второго error framework и без i18n runtime.

## Варианты

| Вариант | Сильная сторона | Цена |
| --- | --- | --- |
| Оставить строки как есть | Нет работы | Расхождение языков, нельзя match причину, C-GOOD-ERR не выполнен (`Error` trait отсутствует) |
| Глобальный каталог строк / fluent | Все тексты в одном файле | Отрыв текста от типа; God catalog; fluent не нужен без localize |
| anyhow везде | Мало boilerplate | Стирает варианты; `ErrorCode` пришлось бы угадывать из текста |
| **Owner thiserror enum + ErrorCode на wire + owner-local UI copy** | Сообщение на варианте, match, English diagnostics | Малый proc-macro; admission при первом вводе |

## Решение

- Каждый owner возвращает свой error enum. `#[error("…")]` (thiserror) или эквивалентный рукописный `Display` задаёт **English**, lowercase, без конечной пунктуации.
- На JSON-RPC/CLI границе сообщение строится из типа + `ErrorCode`; тесты и SDK ветвятся по `code`, не по прозе.
- UI chrome (status, dock, help, command descriptions) — English `&'static str` у **того же owner**, что рисует/отдаёт строку (`src/ui.rs`, `src/tools.rs`). Именованный `const` в том файле — организация. Не fluent, не `t!`, не crate-wide `strings.rs`, не error enum.
- Пользовательский ввод и сохранённые goal/criteria/answers — язык автора, не переводятся кодом.
- Catalog copy вроде `"A planned command in this catalog."` — chrome tools-owner, не недоделанный i18n.
- `thiserror = "2"` (`MIT OR Apache-2.0`) — единственный допущенный helper для этих enum. В `Cargo.toml` попадает только вместе с HZN-001-SOURCE того slice, который его вводит. `anyhow` в owner/public API запрещён.
- Внешний source сохраняется через `#[source]`, кроме secret-bearing parser diagnostics: если `Display` источника включает пользовательскую конфигурацию, владелец сохраняет только безопасное сообщение без исходной строки.

Binds: English source-authored diagnostics and chrome; typed errors; existing `ErrorCode`. Prevents: Russian/other chrome in `src/`, stringly errors, crate-wide error God object, silent anyhow.

## Пересмотр

Явный product-localize (fluent) или доказанная несовместимость thiserror с pin toolchain. Не пересматривать ради вкуса «все строки в одном HashMap».
