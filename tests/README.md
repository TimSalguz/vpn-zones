# Тесты и CI

## Что здесь лежит

- **`harness.nix`** — автономная обвязка без flake-инпутов (у `flake.nix` их
  нет намеренно). Пинует nixpkgs (`nixos-26.05`) и home-manager
  (`release-26.05`) по конкретным коммитам с явными `sha256`, собирает
  home-manager-конфигурацию с `programs.vpn-zones.enable = true` и отдаёт:
  - `activationPackage` — вся конфигурация (для проверки eval);
  - `scripts.<имя>` — каждая script-деривация модуля адресно
    (`vpn-zone`, `vpn-zone-pick`, `vpn-zone-sync`, `vpn-fs-sandbox`,
    `vpn-zone-*-gui`); Rust-крейт сюда не входит — у него свой job;
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
   генератор seccomp-фильтра, слои профилей, генератор `.desktop`-ярлыков и
   ограничитель доступа к композитору `wl-sandbox`) в
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
   отличался бы от CI. Тесты включают и `vpn-zone-seccomp selftest` —
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
- подъём зоны держателем напрямую (без systemd-юнита), внутри зоны:
  `awg0` существует и UP, v4 default через `awg0`, IPv6 выключен (или v6
  default = unreachable), `/etc/resolv.conf` содержит `nameserver 1.1.1.1`
  (дефолт при отсутствии `DNS=`), маршрут до endpoint идёт мимо туннеля;
- контейнер данных: `vpn-zone profile create`, затем `vpn-zone run smoke
  --profile …` с записью файла — маркер обязан оказаться в верхнем слое
  профиля (`~/.local/state/vpn-profiles/<имя>/.config/upper/`) и НЕ появиться
  в настоящем `~/.config`. Это проверка всего пути запуска: `nsenter
  --keep-caps`, свой mount namespace и `vpn-zone-core profile-run`;
- offline-зона: только `lo`, default route нет;
- после `TERM` держателям процессы `pasta` умирают.

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
`smoketest-prof` в `~/.local/state/vpn-profiles` — в начале удаляет их
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
