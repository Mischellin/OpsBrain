# Цель: автономные инфраструктурные изменения с Codex review gates

Epic: [#3](https://github.com/Mischellin/OpsBrain/issues/3). Реализуется **одним** pull request поверх
[#2](https://github.com/Mischellin/OpsBrain/pull/2) (v1), в порядке зависимостей epic.

## Что должно быть сделано

| # | Задача | Модуль |
|---|---|---|
| 4 | OPS-AUTO-01 — adapter общего ReviewService/Codex runner | `auto/review.py`, `auto/runners.py` |
| 5 | OPS-AUTO-02 — Immutable Evidence Bundle и защита секретов | `auto/evidence.py` |
| 6 | OPS-AUTO-03 — Infrastructure preflight: review диагноза и плана | `auto/plan.py`, `auto/preflight.py` |
| 7 | OPS-AUTO-04 — Autonomous ApprovalEngine | `auto/decision.py` |
| 8 | OPS-AUTO-07 — детерминированная проверка фактического состояния | `auto/verify.py` |
| 9 | OPS-AUTO-10 — policy profiles (production, сеть, хранилище, control plane) | `auto/profiles.py` |
| 10 | OPS-AUTO-08 — Codex postflight | `auto/postflight.py` |
| 11 | OPS-AUTO-06 — canary rollout с проверками между стадиями | `auto/rollout.py` |
| 12 | OPS-AUTO-09 — ограниченный autonomous recovery loop | `auto/recovery.py` |
| 13 | OPS-AUTO-11 — E2E и regression fixtures | `tests/test_auto_e2e.py` |
| 14 | OPS-AUTO-05 — STALE approval, optimistic locking, single-use execution | `auto/approval.py` |

## Инварианты (нарушение любого = ревью DENY)

1. Разрешение выдаёт **детерминированный** ApprovalEngine, а не свободный текст модели.
2. Worker и reviewer не имеют прямых production credentials, не меняют active policy, не подделывают
   evidence и не могут самосогласовать свой change.
3. Разрешение действительно только для проверенных plan / arguments / targets / evidence / policy.
   Любое изменение входа делает approval **STALE** и требует нового preflight review.
4. Timeout, quota, disagreement, неизвестный target и недостаток доказательств **не означают PASS**.
   После ограниченных попыток — `BLOCKED_AUTONOMOUSLY`, без повторного запроса `yes`.
5. Успешный return code ≠ достижение цели: нужны фактические post-checks и проверка регрессий.
6. Canary и rollback применяются только при подтверждённой пригодности; непокрытые политикой действия
   блокируются.
7. Claude не является зависимостью. Модели и лимиты конфигурируются, скрытого платного fallback нет.

## Проверки

`ruff`, `mypy --strict` и `pytest` проходят в проектном окружении. Live-проверки, требующие реальных
credentials, помечаются как пропущенные, а не выдаются за выполненные.

## Состояние

Обновляется по мере готовности. Формат: `готово / в работе / не начато`.
