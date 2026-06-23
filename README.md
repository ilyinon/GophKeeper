GophKeeper — клиент-серверное хранилище приватных данных: логинов, паролей,
токенов, файлов и других секретов.

## Реализация

Проект сделан как gRPC-only система с opaque-хранением: сервер не знает тип
секрета и не имеет доступа к plaintext. Все пользовательские данные шифруются
на клиенте перед отправкой на сервер.


* сервер не знает тип и содержимое секрета;
* клиент собирает секрет в JSON, шифрует его через AES-256-GCM и отправляет
  на сервер только nonce + ciphertext;
* сервер хранит только `user_id`, `item_id`, `revision`, `sync_version`, `nonce`, `ciphertext` и tombstone удаления;
* JWT используется для авторизации gRPC-запросов;
* PostgreSQL хранит серверные данные;
* SQLite на клиенте хранит локальный encrypted cache для офлайн-чтения ранее синхронизированных секретов.

### Версионирование и синхронизация

У каждой записи есть `revision`. `UpdateItem` и `DeleteItem` принимают `expected_revision`; при несовпадении сервер возвращает conflict.

У каждого изменения есть `sync_version`. Клиент хранит `last_sync_version` в SQLite и вызывает `Sync(after_sync_version)`, чтобы получить новые encrypted blobs и tombstone удаления.

### Локальный кэш

SQLite-кэш не хранит plaintext. В нём лежат:

* сессия пользователя и JWT;
* `kdf_salt`;
* `last_sync_version`;
* encrypted vault items.

Для чтения секрета из кэша клиенту всё равно нужен master password, из которого локально выводится AES-ключ.

Параметры Argon2id для вывода vault-key настраиваются через переменные окружения клиента:

* `GOPHKEEPER_VAULT_KDF_MEMORY` — память в KiB, по умолчанию `65536`;
* `GOPHKEEPER_VAULT_KDF_ITERATIONS` — число итераций, по умолчанию `3`;
* `GOPHKEEPER_VAULT_KDF_PARALLELISM` — параллелизм, по умолчанию `4`.

### Сборка и тесты

```bash
make proto
make swagger
make test
make functional
make build
```


### Swagger

Описание протокола взаимодействия клиента и сервера находится в формате
Swagger 2.0:

```text
docs/swagger/gophkeeper.swagger.json
```

Основной транспорт проекта — gRPC. Swagger-файл автоматически генерируется
из `api/proto/gophkeeper/v1/gophkeeper.proto` командой `make swagger`,
документирует HTTP/JSON-форму того же proto-контракта и содержит расширения
`x-grpc-service` и `x-grpc-method`, чтобы было видно, как REST-подобные
операции соответствуют gRPC-методам.

Особенности формата:

* авторизация описана через заголовок `Authorization: Bearer <jwt>`;
* поля `bytes` (`kdf_salt`, `nonce`, `ciphertext`) описаны как base64-строки;
* `revision` используется для optimistic concurrency;
* `sync_version` используется как cursor синхронизации.

Проверить корректность Swagger JSON:

```bash
make swagger
```

Функциональные тесты написаны на Python `unittest` и проверяют реальные бинарники через CLI:

* сборка клиента и сервера;
* запуск gRPC-сервера с PostgreSQL;
* регистрация и логин;
* создание всех типов секретов;
* чтение, список, обновление, удаление;
* optimistic conflict по `revision`;
* синхронизация второго клиента;
* offline-чтение из SQLite cache;
* изоляция данных разных пользователей;
* отсутствие plaintext-секретов в SQLite cache.

По умолчанию тесты используют PostgreSQL из `docker-compose.yml`:

```bash
make up
make functional
```

Для другой БД:

```bash
GOPHKEEPER_FUNC_DATABASE_URL='postgres://user:password@localhost:5432/gophkeeper?sslmode=disable' \
make functional
```

### Доставка клиента через GitHub

Клиент распространяется через GitHub Releases. Workflow
`.github/workflows/release.yml` запускается при публикации git-тега `v*` и собирает
`gophkeeper-client` для:

* Linux amd64/arm64;
* macOS amd64/arm64;
* Windows amd64/arm64.

Каждый архив содержит CLI-бинарник и README. Для проверки целостности рядом
публикуется `.sha256` файл.

Публикация релиза:

```bash
git tag v1.0.0
git push origin v1.0.0
```

После выполнения GitHub Actions пользователь скачивает подходящий архив со
страницы GitHub Releases:

* `gophkeeper-client_v1.0.0_linux_amd64.tar.gz`;
* `gophkeeper-client_v1.0.0_linux_arm64.tar.gz`;
* `gophkeeper-client_v1.0.0_darwin_amd64.tar.gz`;
* `gophkeeper-client_v1.0.0_darwin_arm64.tar.gz`;
* `gophkeeper-client_v1.0.0_windows_amd64.zip`;
* `gophkeeper-client_v1.0.0_windows_arm64.zip`.

### Запуск сервера

```bash
GOPHKEEPER_DATABASE_URL='postgres://user:password@localhost:5432/gophkeeper?sslmode=disable' \
GOPHKEEPER_JWT_SECRET='change-me-change-me-change-me-32-bytes' \
./bin/gophkeeper-server --listen 127.0.0.1:3200
```

Опционально можно включить TLS:

```bash
./bin/gophkeeper-server --tls-cert server.crt --tls-key server.key
```

### CLI

```bash
./bin/gophkeeper-client register --login test_user --password 'v3R1$EcP4s$w0rD'
./bin/gophkeeper-client login --login test_user --password 'v3R1$EcP4s$w0rD'

./bin/gophkeeper-client add --password 'v3R1$EcP4s$w0rD' \
  --type login_password \
  --name github \
  --metadata site=github.com \
  --username test_user \
  --secret 'secret-password'

./bin/gophkeeper-client sync
./bin/gophkeeper-client list --password 'v3R1$EcP4s$w0rD'
./bin/gophkeeper-client get ITEM_ID --password 'v3R1$EcP4s$w0rD' --offline
./bin/gophkeeper-client version
```
