# ADR-0005: однократные CI-проверки и продвижение проверенного артефакта

- Status: accepted
- Date: 2026-11-16
- Основание: запрос оператора переработать CI/CD и устранить повтор тестов между test/package.

## Context

Исходный workflow повторно исполнял integration targets и doctests, терял
Linux sandbox prerequisites в package VM и давал нескольким matrix jobs право
изменять один Release. Совпадение source SHA повторных сборок не удостоверяло
байты поставляемого bundle.

## Decision

Каждый native test job владеет своим неизменяемым bundle и одним исполнением
Cargo targets. Family receipts проецируются из проверенных логов, а не запускают
те же targets повторно. Verify потребляет bundle/receipts того же workflow run;
разрешённый cross-host fold сохраняется с проверкой обоих native candidates.
Publisher один, без checkout и запуска кода кандидата, с единственным write token.
Технический контракт и команды — [CI/CD](../ci-cd.md); основания —
[22 первоисточника](../../research/ci-cd-design.md).

## Consequences

Передача tar.gz и проверка hashes сложнее повторного `cargo test` внутри package,
но устраняет повтор и разрыв идентичности кандидата. Compilation cache не является
evidence. Отказ от cross-host checks ради дешёвого зелёного CI отвергнут; они
остаются реальными локальными native проверками. Изменение не разрешает движение
существующих тегов и не ослабляет локальный §14 gate.
