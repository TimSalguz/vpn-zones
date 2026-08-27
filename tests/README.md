# Тесты и CI

## Что здесь лежит

- **`harness.nix`** — автономная обвязка без flake-инпутов (у `flake.nix` их
  нет намеренно). Пинует nixpkgs (`nixos-26.05`) и home-manager
  (`release-26.05`) по конкретным коммитам с явными `sha256`, собирает
  home-manager-конфигурацию с `programs.vpn-zones.enable = true` и отдаёт:
  - `activationPackage` — вся конфигурация (для проверки eval);
  - `scripts.<имя>` — каждая script-деривация модуля адресно
    (`vpn-zone`, `vpn-zone-pick`, `vpn-zone-sync`, `vpn-zone-*-gui`);
    Rust-крейт сюда не входит — у него свой job;
  - `zoneHolder` — запускаемая обёртка над держателем зоны
    (`zone-holder <имя>` = то, что делает юнит `vpn-zone@<имя>`, но без
    systemd; строка ExecStart берётся из самого модуля вместе с путями
    к `ip`/`awg`/`wg`/`pasta`);
  - `zoneHolderExec` — строка ExecStart юнита (для диагностики);
  - `smokeTools` — buildEnv c `wireguard-tools`, `iproute2`, `util-linux`, `passt` тех же
    версий, что у модуля.

  Username и домашний каталог параметризуются:
  `--argstr username … --argstr homeDirectory …` (по умолчанию
  `runner` / `/home/runner`).

- **`integration/smoke.sh`** — смоук: поднимает настоящую зону в
  непривилегированном userns и проверяет её изнутри через `nsenter`.

## Что гоняет CI (`.github/workflows/ci.yml`)

На каждый push и pull request, раннер `ubuntu-24.04`:

1. **eval** — `nix-instantiate tests/harness.nix -A activationPackage …`:
   полный eval модуля, падает на любой ошибке вычисления.
2. **scripts** — адресная сборка каждой `scripts.<имя>`, затем `shellcheck`
   по собранным `bin/*` (файлы без шебанга пропускаются). Список исключений
   shellcheck с обоснованием — прямо в шаге workflow.
3. **rust** — крейт `rust/` (жизненный цикл зоны, парсер конфигов WG/AWG,
   генератор seccomp-фильтра, слои профилей, генератор `.desktop`-ярлыков,
   ограничитель доступа к композитору `wl-sandbox` и песочница файловой
   системы `fs-sandbox`) в
   `nix-shell tests/harness.nix -A rustShell`: `cargo fmt --check`,
   `cargo clippy --all-targets -- -D warnings`, `cargo test`. Юниты крейта
   покрывают грабли §1–§5, §7 и §10 из `docs/GOTCHAS.md`: у зоны — разбор
   аргументов держателя, разбор default-маршрута обоих видов (с via и без),
   выбор IPv6-стратегии, resolv.conf по умолчанию, литерал/имя в Endpoint
   (привилегированную часть жизненного цикла проверяет смоук); у генератора
   ярлыков — разбор `.desktop`, отсутствие кавычек в `Exec`, битые симлинки,
   идемпотентная запись, уборка чужого не трогает. У `wl-sandbox` проверяются fallback-пути:
   композитора на раннере нет, а программа обязана всё равно запуститься и
   сказать об ослабленной защите в stderr; окружение в этих тестах чистится
   нарочно — на машине разработчика композитор есть, и без чистки результат
   отличался бы от CI. У `fs-sandbox` так же: без namespace проверяются
   разбор argv, права (включая старые файлы с пробелами и кавычками),
   построение списка аргументов bwrap как чистой функции — поэлементно, потому
   что ПОРЯДОК операций и есть песочница, — генерация `/.flatpak-info`, выбор
   номера дисплея и узлы GPU; а сквозные проверки в `rust/tests/`
   подставляют вместо bwrap скрипт и смотрят, что без графики доступов
   записывается пусто и диалог не зовётся, что недоступный dbus-прокси не
   мешает запуску и что фильтр приезжает на том дескрипторе, который назван в
   `--seccomp`. Тесты, которым нужен НАСТОЯЩИЙ bwrap, помечены `#[ignore]`:
   userns на раннере готовит только job integration, а `cargo test` идёт без
   этой подготовки — их закрывает смоук (`cargo test -- --ignored`, чтобы
   прогнать руками). Тесты включают и `vpn-zone-seccomp selftest` —
   фильтр грузится в отдельный процесс и проверяется, что `keyctl` отвечает
   EPERM (прав для этого не нужно: seccomp с NO_NEW_PRIVS доступен
   непривилегированно). В деривации модуля тесты выключены (`doCheck = false`):
   там их гонять негде.
4. **integration** — подготовка раннера (снять AppArmor-запрет на userns,
   `modprobe wireguard`, `uidmap` + диапазоны в `/etc/subuid`/`subgid`) и
   запуск `tests/integration/smoke.sh`.

## Что проверяет смоук

- `vpn-zone add` из синтетического конфига (ключи `wg genkey`, endpoint
  `192.0.2.1` из TEST-NET — недостижим, рукопожатие не нужно), плюс тот же
  конфиг в CRLF;
- подъём зоны держателем напрямую (без systemd-юнита) и **герметичность
  шлюзовой архитектуры** (`docs/LEAK-MODEL.md`): в namespace приложений
  (`zone.pid`) ровно два линка — `lo` и `awg0`, и больше ничего; `awg0` UP, v4
  default через него, v6 default отсутствует или `unreachable`,
  `/etc/resolv.conf` содержит `nameserver 1.1.1.1` (дефолт при отсутствии
  `DNS=`), а маршрут до endpoint идёт В ТУННЕЛЬ — петли нет, потому что
  шифрованный трафик рождается в другом namespace. В аплинке (`uplink.pid`)
  для контраста: интерфейс pasta (`hostif`), default route и НЕТ `awg0` — он
  там создаётся и сразу переезжает вниз;
- контейнер данных: `vpn-zone profile create`, затем `vpn-zone run smoke
  --profile …` с записью файла — маркер обязан оказаться в верхнем слое
  профиля (`~/.local/state/vpn-profiles/<имя>/.config/upper/`) и НЕ появиться
  в настоящем `~/.config`. Это проверка всего пути запуска: `nsenter
  --keep-caps`, свой mount namespace и `vpn-zone-core profile-run`;
- песочница файловой системы (`vpn-zone-core fs-sandbox`): пути инструментов
  грепаются ИЗ СОБРАННОГО текста `vpn-zone` — они зашиты туда флагами
  `--bwrap/--dbus-proxy/--kdialog/--xwayland`, так что проверяется ровно то, что
  поедет пользователю. Внутри песочницы `$HOME` пуст, маркер из настоящего дома
  не виден, `/nix/store` виден; файл доступов создан и пуст (без графики
  спрашивать негде), а подставной kdialog не вызывался ни разу — если бы
  вызвался, оставил бы свидетеля. Отдельно: с заведомо недоступным dbus-прокси
  запуск обязан жить и донести код выхода программы (42) — раньше сокет
  несуществующего прокси биндился безусловно и bwrap падал;
- offline-зона: только `lo`, default route нет (аплинка и pasta у неё нет вовсе);
- после `TERM` держателям процессы `pasta` умирают — ищутся по `--netns
  /proc/<uplink.pid>/ns/net`, то есть ровно по тому признаку, по которому их
  находит и `vpn-zone gc`.

**Важно:** на раннере нет модуля `amneziawg`, поэтому смоук рассчитывает на
fallback в держателе зоны (`vpn-zone-core zone-holder`, `rust/src/zone.rs`):
если `ip link add … type amneziawg` не удался и в конфиге нет параметров
обфускации (Jc/S1/S2/H1–4/I1–5), поднимается ядерный `wireguard` (утилитой
`wg`) на том же имени `awg0`. Также ожидается дефолтный DNS `1.1.1.1` при
отсутствии `DNS=` в конфиге.

## Запустить смоук у себя

Требования — те же, что у самого модуля (см. корневой README): userns без
привилегий, диапазон в `/etc/subuid`/`/etc/subgid`, `newuidmap`,
`/dev/net/tun`, ядерный модуль `wireguard` или `amneziawg`.

```sh
tests/integration/smoke.sh
```

Скрипт сам собирает нужное из `harness.nix` под твои `$USER`/`$HOME`
(первый запуск скачает замыкание kdialog и прочего — это долго, но это
загрузка из кэша, не компиляция). Использует зоны с именами `smoke`,
`smoke-crlf`, `offsmoke` в `~/.local/state/vpn-zones` и профиль
`smoketest-prof` в `~/.local/state/vpn-profiles` и набор доступов
`smoke-fsapp` в `~/.config/vpn-zones/fs-perms` — в начале удаляет их
остатки, чужие зоны и профили не трогает (шаблоны `pkill`/`pgrep` сужены до
тестовых имён). Если зона с таким именем уже поднята — откажется и попросит
опустить.

## Обновить пины

```sh
git ls-remote https://github.com/NixOS/nixpkgs refs/heads/nixos-XX.YY
nix-prefetch-url --unpack https://github.com/NixOS/nixpkgs/archive/<rev>.tar.gz
# то же для home-manager (ветка release-XX.YY), затем вписать rev+sha256
# в tests/harness.nix и поправить home.stateVersion под ветку.
```
