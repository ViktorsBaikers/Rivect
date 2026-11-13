# ADR-0003: явный SQL на rusqlite, без ORM

Status: ACCEPTED (уточнение ADR-0001 / SRC-006; пользователь 2026-09-10 поручил исследовать замену plain SQL).
Date: 2026-09-10.
Sources: [rusqlite 0.40.2](https://docs.rs/rusqlite/latest/rusqlite/); [sqlx compile-time](https://github.com/transact-rs/sqlx); [Diesel compare](https://diesel.rs/compare/compare_diesel/); [sea-query](https://docs.rs/sea-query/latest/sea_query/); [rusqlite_migration 2.6.0](https://docs.rs/rusqlite_migration/latest/rusqlite_migration/); [research/sqlite-access.md](../../research/sqlite-access.md); `.devrites/principles.md` P-002.

## Контекст

State owner уже сериализует CAS/outbox/ledger в одном SQLite writer. `state.rs` содержит длинный SQL inline. Вопрос: упрощает ли Diesel/SQLx/SeaORM этот код.

## Варианты

| Вариант | Почему отклонён или принят |
| --- | --- |
| Заменить на Diesel / SeaORM | DSL/ORM скрывает FTS5, PRAGMA, наши constraints; второй stack против ADR-0001 |
| Заменить на sqlx | Async pool и `DATABASE_URL`/`sqlx-cli` не совпадают с sync one-writer и runtime-created schema |
| Добавить sea-query «поверх» rusqlite | Второй SQL AST без второго потребителя; FTS5/DDL всё равно raw |
| **Оставить rusqlite, вынести SQL в файлы/константы** | Принято сейчас: организация без новых runtime crate |
| rusqlite_migration | Принято **когда** появится вторая schema generation; не для текущего единственного `CREATE IF NOT EXISTS` |

## Решение

Единственный доступ к SQLite — `rusqlite` (bundled), как в ADR-0001. Новые запросы и DDL:

1. Живут в `src/state/sql/` (`include_str!`) или `const` в `src/state/queries.rs`, не как анонимные литералы внутри бизнес-функций, кроме однострочных pragma/exists, где вынос хуже читаемости.
2. Параметры только через `params!` / `named_params!`.
3. Результаты — типизированные structs и `query_map`/`query_row`.
4. Вторая schema generation вводится через `rusqlite_migration` после source admission; WAL/synchronous PRAGMA остаются вне migration SQL. `user_version` тогда принадлежит миграциям.

Binds: one SQLite stack, explicit SQL, typed rows. Prevents: ORM/query-builder rewrite, compile-time database for sqlx macros, занятие `user_version` до введения миграций.

## Пересмотр

Только если rusqlite перестанет закрывать обязательный контракт (WAL/FTS5/bundled version gate) — тогда адресный пересмотр ADR-0001, не локальный «попробуем Diesel».
