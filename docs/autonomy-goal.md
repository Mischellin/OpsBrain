# Цель: автономные инфраструктурные изменения с Codex review gates

Epic: [#3](https://github.com/Mischellin/OpsBrain/issues/3). База — [#2](https://github.com/Mischellin/OpsBrain/pull/2) (v1),
который мержит владелец. Реализуется **стеком из 11 pull request** поверх #2, в порядке зависимостей epic,
мерж снизу вверх (решение владельца 2026-10-04).

## Формат поставки

Один сводный PR на все 11 задач был отклонён: это ~5000 строк поверх неслитого #2 — нереально
ревьюить и опасно откатывать. Вместо этого каждый PR — одна задача, база — ветка предыдущего,
и на каждом стоит `@codex review`. GitHub сам перенаправит базу на `main`, когда #2 смёржится.

## Порядок и текущее состояние

| # | Задача | Модуль | PR | Состояние |
|---|---|---|---|---|
| 4 | OPS-AUTO-01 — ReviewService/Codex runner | `auto/review.py`, `auto/runners.py` | [#15](https://github.com/Mischellin/OpsBrain/pull/15) | готово, 1 круг замечаний закрыт |
| 5 | OPS-AUTO-02 — Evidence Bundle | `auto/evidence.py` | [#16](https://github.com/Mischellin/OpsBrain/pull/16) | готово, замечания открыты |
| 8 | OPS-AUTO-07 — проверка фактического состояния | `auto/verify.py` | [#17](https://github.com/Mischellin/OpsBrain/pull/17) | готово, замечания открыты |
| 6 | OPS-AUTO-03 — preflight плана | `auto/plan.py`, `auto/preflight.py` | [#18](https://github.com/Mischellin/OpsBrain/pull/18) | готово, ревью идёт |
| 7 | OPS-AUTO-04 — ApprovalEngine | `auto/decision.py` | — | не начато |
| 14 | OPS-AUTO-05 — STALE approval, optimistic locking, single-use lease | `auto/approval.py` | — | не начато |
| 9 | OPS-AUTO-10 — policy profiles | `auto/profiles.py` | — | не начато |
| 10 | OPS-AUTO-08 — Codex postflight | `auto/postflight.py` | — | не начато |
| 11 | OPS-AUTO-06 — canary rollout | `auto/rollout.py` | — | не начато |
| 12 | OPS-AUTO-09 — bounded recovery loop | `auto/recovery.py` | — | не начато |
| 13 | OPS-AUTO-11 — E2E и regression fixtures | `tests/test_auto_e2e.py` | — | не начато |

## Правило очерёдности

**Новые задачи не начинаются, пока не закрыты P1-замечания `@codex review` в уже открытых PR.**

Причина конкретная: замечания бьют не в детали, а в конструкцию — «id не сверяется со своим хешем»,
«непривязанное доказательство проходит для любого change», «свежесть измеряет время подачи, а не
наблюдения». Этот же приём воспроизведён в `ChangePlan` (#6), потому что был скопирован из
`EvidenceBundle`. Строить седьмой модуль до этого — значит размножать один и тот же дефект по стеку.

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
8. Content-addressed id обязан проверяться против хеша содержимого при каждой верификации. Запись под
   существующим id с пересчитанным digest — не иммутабельность.

## Проверки

`ruff`, `mypy --strict` и `pytest` проходят в проектном окружении. Live-проверки, требующие реальных
credentials, помечаются как пропущенные, а не выдаются за выполненные.

Отдельно: `@codex review` нужно ставить **повторно** после каждого пуша в PR. Комментарий, оставленный
на старом коммите, не обновляется сам, и ревью считается пройденным устаревшей версии.

## Готово, когда

- [x] #4, #5, #6, #8 реализованы, покрыты тестами и стоят в стеке.
- [ ] P1-замечания Codex закрыты во всех открытых PR; на каждом — свежее `@codex review` без P1.
- [ ] Остальные 7 задач реализованы в том же формате.
- [ ] Сквозной разрешённый сценарий проходит без human `yes`; неопределённый заканчивается
      `BLOCKED_AUTONOMOUSLY` без мутаций.
- [ ] Restart/retry не дублирует apply.
- [ ] Документированы запуск, scopes, бюджеты, emergency stop и реально проверенные платформы.
