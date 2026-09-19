# OpsBrain - руководство

OpsBrain - локальный MCP-сервер, через который Claude управляет инфраструктурой дёшево по токенам и безопасно.

## Установка за 5 минут

```bash
uv tool install git+https://github.com/Mischellin/OpsBrain.git
opsbrain init              # пример конфига в ~/.opsbrain/config.yaml - опишите хосты, стеки, плейбуки
opsbrain doctor --net      # проверка конфига, бинарей и ssh-доступности
claude mcp add --scope user OpsBrain -- opsbrain serve
```

Секретов в конфиге нет. OpsBrain использует то, что уже работает на машине: ssh-agent, kubeconfig, файл пароля
ansible-vault; env-файл tofu остаётся на раннере и только `source`-ится там.

## Как с этим работать

Говорите с Claude как обычно - он сам выбирает инструмент:

- «что сейчас с инфрой?» -> `overview`, `docs status`, `hosts status`, `k8s overview`, `observe alerts`
- «есть ли дрейф?» -> `drift` (tofu plan + плейбуки в `--check` + экспорт роутера) - один вызов, один короткий ответ
- «почему падает pod X?» -> `k8s describe` / `k8s logs` - шаблоны сообщений со счётчиками вместо тысячи строк
- «накати common на ops-01» -> `ansible check` -> вы подтверждаете -> `ansible apply`

Сырой вывод не попадает в диалог: он лежит на диске артефактом (секреты вырезаны), Claude читает кусок или grep
только если сводки мало.

## Изменения: всегда в два шага

1. Claude делает `plan` / `check` и получает **change id** с кратким описанием того, что изменится.
2. Вы в терминале: `opsbrain changes` -> `opsbrain approve c-xxxxxxxx` (покажет сводку, попросит набрать `yes`).
   Если план уничтожает или пересоздаёт ресурсы - нужен флаг `--allow-destroy` и ввод id изменения.
3. Claude вызывает `apply` с этим id. Применяется **ровно сохранённый план**; id одноразовый и живёт час.

Claude подтвердить не может: команды approve в MCP нет, а CLI отказывается работать без интерактивного терминала.
Ansible-изменение аннулируется, если после проверки изменился любой файл в каталоге ansible. Роутер OpsBrain
не меняет никогда - только читает `/export hide-sensitive`.

Что разрешить без подтверждения - решаете вы в `policy` (например `"k8s.refresh": allow`), `deny` всегда сильнее.

## Долгие операции

`tofu plan/apply`, плейбуки и drift запускаются отвязанно (nohup, лог + rc-файл): таймаут MCP или обрыв ssh их не
прерывает. Если операция не успела за `wait_s`, Claude получает id задания и опрашивает `job status`.

## Сколько сэкономлено

```bash
opsbrain stats     # вызовы, сырые байты против возвращённых, оценка сэкономленных токенов
```

## Подключение к DevBrain

`opsbrain serve --http` (127.0.0.1:8765, токен в `~/.opsbrain/http.token`), затем в конфиге проекта DevBrain -
http-коннектор на `http://host.docker.internal:8765/mcp` и `devbrain secret set opsbrain`. `opsbrain install`
печатает готовые фрагменты.
