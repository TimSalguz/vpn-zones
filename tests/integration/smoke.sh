#!/usr/bin/env bash
# Смоук-тест vpn-zones: поднимает настоящую зону в непривилегированном userns
# и проверяет её изнутри. Работает без systemd --user юнита: держатель зоны
# запускается напрямую (атрибут zoneHolder из tests/harness.nix).
#
# РАСЧЁТ НА FALLBACK: на CI-раннере нет модуля amneziawg, поэтому тест
# предполагает, что держатель зоны (`vpn-zone-core zone-holder`, rust/src/zone.rs)
# при неудаче `ip link add … type amneziawg` и конфиге БЕЗ параметров
# обфускации (Jc/S1/S2/H1-4/I1-5) поднимает ядерный wireguard (утилитой wg) на
# том же имени интерфейса awg0.
#
# Endpoint — 192.0.2.1 (TEST-NET-1, недостижим): рукопожатие для смоука не
# нужно, проверяется сама механика зоны, а не живость сервера.
#
# АРХИТЕКТУРА, КОТОРУЮ ЭТО ПРОВЕРЯЕТ (docs/LEAK-MODEL.md): у зоны ДВА сетевых
# namespace. В uplink-ns (uplink.pid) живут pasta и UDP-сокет туннеля; в app-ns
# (zone.pid — туда же ходит nsenter из vpn-zone run/status) нет ничего, кроме lo
# и awg0. Главный ассерт теста — именно это «ничего, кроме»: пока других
# интерфейсов нет, утечка невозможна не по правилу, а по отсутствию пути.
#
# Тест использует зоны с именами smoke, smoke-crlf, offsmoke в
# ~/.local/state/vpn-zones и профиль smoketest-prof в ~/.local/state/vpn-profiles
# — и удаляет их же в начале.
set -euo pipefail

step() { printf '\n==> %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
HARNESS="$REPO_ROOT/tests/harness.nix"
WORK=$(mktemp -d)
STATE="$HOME/.local/state/vpn-zones"
PROFILES="$HOME/.local/state/vpn-profiles"
TEST_ZONES=(smoke smoke-crlf offsmoke)
TEST_PROFILE=smoketest-prof
MARKER="$HOME/.config/vpn-smoke-marker"
HOLDER_PIDS=()

cleanup() {
  rc=$?
  set +e
  for p in "${HOLDER_PIDS[@]}"; do kill -TERM "$p" 2>/dev/null; done
  # Оба namespace зоны: держатель гасит их вместе, но если он сам уже убит,
  # аплинк остался бы висеть с pasta на шее.
  for z in "${TEST_ZONES[@]}"; do
    for f in zone.pid uplink.pid; do
      zp=$(cat "$STATE/$z/$f" 2>/dev/null)
      [ -n "$zp" ] && kill -TERM "$zp" 2>/dev/null
    done
  done
  # Подстраховка для зон, поднятых ДОРУСТОВОЙ версией модуля: там процесс зоны
  # назывался vpn-zone-init и юниту тут не подчинялся. У нынешнего держателя
  # (`vpn-zone-core zone-holder`) зона и её зеркало состояния гаснут вместе с
  # процессом, которому мы уже послали TERM, так что шаблон обычно не находит
  # ничего. Шаблон сужен до ИМЁН ТЕСТОВЫХ зон: голый «vpn-zone-init» убил бы и
  # настоящие зоны, если смоук гоняют на рабочей машине.
  for z in "${TEST_ZONES[@]}"; do
    pkill -TERM -f "vpn-zone-init $z\$" 2>/dev/null
  done
  # Контейнер данных и его записи в реестре запусков. Маркер в настоящем
  # ~/.config появляется только при провале теста (слой не наложился), но
  # убрать его всё равно надо — чужого файла с таким именем не бывает.
  rm -rf "${PROFILES:?}/$TEST_PROFILE" "${STATE:?}/.running/$TEST_PROFILE"
  rm -f "$MARKER"
  if [ "$rc" -ne 0 ]; then
    for z in smoke offsmoke; do
      if [ -s "$WORK/holder-$z.log" ]; then
        printf -- '--- журнал держателя %s ---\n' "$z"
        cat "$WORK/holder-$z.log"
      fi
    done
  fi
  rm -rf "$WORK"
  exit "$rc"
}
trap cleanup EXIT

# --- 0. Сборка обвязки -------------------------------------------------------
step "Собираю обвязку из $HARNESS (username=$(id -un), home=$HOME)"
build() {
  nix-build "$HARNESS" \
    --argstr username "$(id -un)" --argstr homeDirectory "$HOME" \
    -A "$1" -o "$WORK/$2" >/dev/null
}
build scripts.vpn-zone vpn-zone
build zoneHolder zone-holder
build smokeTools tools

VPN_ZONE="$WORK/vpn-zone/bin/vpn-zone"
ZONE_HOLDER="$WORK/zone-holder/bin/zone-holder"
WG="$WORK/tools/bin/wg"
IP="$WORK/tools/bin/ip"
NSENTER="$WORK/tools/bin/nsenter"
UNSHARE="$WORK/tools/bin/unshare"

# --- 1. Предусловия ----------------------------------------------------------
step "Проверяю предусловия раннера"
u=$(id -un)
grep -q "^$u:" /etc/subuid || fail "в /etc/subuid нет диапазона для $u"
grep -q "^$u:" /etc/subgid || fail "в /etc/subgid нет диапазона для $u"
[ -c /dev/net/tun ] || fail "нет /dev/net/tun"
command -v newuidmap >/dev/null || fail "нет newuidmap (пакет uidmap)"
"$UNSHARE" --user --map-root-user true || fail "непривилегированные userns запрещены"
echo "ok: subuid/subgid, tun, newuidmap, userns"

step "Убираю остатки прошлых прогонов"
for z in "${TEST_ZONES[@]}"; do
  zp=$(cat "$STATE/$z/zone.pid" 2>/dev/null || true)
  if [ -n "$zp" ] && [ -d "/proc/$zp" ]; then
    fail "зона $z уже поднята (pid $zp) — сначала опусти её"
  fi
  rm -rf "${STATE:?}/$z"
done
rm -rf "${PROFILES:?}/$TEST_PROFILE" "${STATE:?}/.running/$TEST_PROFILE"
rm -f "$MARKER"

# --- 2. Синтетический конфиг -------------------------------------------------
step "Генерирую синтетический конфиг WireGuard (без DNS=, без обфускации)"
priv=$("$WG" genkey)
peerpub=$("$WG" genkey | "$WG" pubkey)
cat > "$WORK/smoke.conf" <<EOF
[Interface]
PrivateKey = $priv
Address = 10.99.0.2/32

[Peer]
PublicKey = $peerpub
AllowedIPs = 0.0.0.0/0
Endpoint = 192.0.2.1:51820
EOF
echo "ok: $WORK/smoke.conf"

# --- 3. vpn-zone add ---------------------------------------------------------
step "vpn-zone add smoke"
"$VPN_ZONE" add smoke "$WORK/smoke.conf"
[ -d "$STATE/smoke" ] || fail "каталог зоны не появился"
[ -f "$STATE/smoke/config.conf" ] || fail "конфиг не скопирован в зону"
grep -q "PrivateKey" "$STATE/smoke/config.conf" || fail "в копии конфига нет PrivateKey"
echo "ok: зона создана, конфиг скопирован"

step "vpn-zone add smoke-crlf (тот же конфиг в CRLF)"
sed 's/$/\r/' "$WORK/smoke.conf" > "$WORK/smoke-crlf.conf"
"$VPN_ZONE" add smoke-crlf "$WORK/smoke-crlf.conf"
if grep -q $'\r' "$STATE/smoke-crlf/config.conf"; then
  fail "add не вычистил CRLF из конфига"
fi
echo "ok: CRLF-конфиг принят и нормализован"

# --- 4. Поднимаем зону держателем (без systemd) ------------------------------
step "Поднимаю зону smoke держателем: $ZONE_HOLDER smoke"
"$ZONE_HOLDER" smoke >"$WORK/holder-smoke.log" 2>&1 &
HOLDER_PIDS+=("$!")

wait_file() { # <файл> <попыток по 0.1с>
  local i
  for ((i = 0; i < $2; i++)); do
    [ -f "$1" ] && return 0
    sleep 0.1
  done
  return 1
}
wait_file "$STATE/smoke/ready" 200 || fail "зона smoke не поднялась за 20 секунд"
ZPID=$(cat "$STATE/smoke/zone.pid")
[ -d "/proc/$ZPID" ] || fail "ready есть, а процесса зоны (pid $ZPID) нет"
# Второй namespace шлюзовой архитектуры: связность и UDP-сокет туннеля живут в
# нём, приложения его не видят. Файл появляется РАНЬШЕ ready (uplink стартует
# первым), но ждём явно — на случай гонки при медленном раннере.
wait_file "$STATE/smoke/uplink.pid" 200 || fail "uplink.pid не появился"
UPID=$(cat "$STATE/smoke/uplink.pid")
[ -d "/proc/$UPID" ] || fail "uplink.pid есть, а процесса аплинка (pid $UPID) нет"
[ "$UPID" != "$ZPID" ] || fail "uplink.pid и zone.pid совпали — namespace один, а должно быть два"
echo "ok: зона smoke поднята, app-ns pid $ZPID, uplink pid $UPID"

in_zone() {
  "$NSENTER" --preserve-credentials -U -n -m -t "$ZPID" -- "$@"
}
in_uplink() {
  "$NSENTER" --preserve-credentials -U -n -m -t "$UPID" -- "$@"
}

# --- 5. Проверки внутри зоны -------------------------------------------------
# ГЛАВНЫЙ АССЕРТ ГЕРМЕТИЧНОСТИ (docs/LEAK-MODEL.md). Всё остальное — маршруты,
# IPv6, DNS — производные от него: если в namespace приложений нет ничего, кроме
# lo и туннеля, то утечь некуда физически, каким бы ни было семейство протоколов
# и что бы ни напутали в маршрутах.
step "Внутри зоны: РОВНО два линка — lo и awg0, больше ничего"
links=$(in_zone "$IP" -o link show)
echo "$links"
n=$(echo "$links" | wc -l)
[ "$n" -eq 2 ] || fail "в app-ns $n интерфейсов вместо двух — герметичность нарушена"
echo "$links" | grep -q ': lo:' || fail "в app-ns нет lo"
echo "$links" | grep -q ': awg0[:@]' || fail "в app-ns нет awg0"

step "Внутри зоны: интерфейс awg0 существует и UP"
linkline=$(in_zone "$IP" -o link show awg0) || fail "внутри зоны нет интерфейса awg0"
echo "$linkline"
echo "$linkline" | grep -q '[<,]UP[,>]' || fail "awg0 не поднят (нет флага UP)"

step "Внутри зоны: v4 default route через awg0"
def4=$(in_zone "$IP" -4 route show default)
echo "${def4:-<пусто>}"
echo "$def4" | grep -q 'dev awg0' || fail "default route не через awg0"

step "Внутри зоны: IPv6 без пути наружу (конфиг без v6)"
# Проверки disable_ipv6 больше нет: семейство не выключается, потому что и не
# нужно — других интерфейсов в app-ns не существует. Достаточно, чтобы v6
# default либо отсутствовал, либо был unreachable (пояс с подтяжками).
if ! in_zone test -e /proc/sys/net/ipv6; then
  echo "ok: IPv6 в ядре нет"
else
  def6=$(in_zone "$IP" -6 route show default 2>/dev/null || true)
  echo "v6 default: ${def6:-<пусто>}"
  if [ -z "$def6" ]; then
    echo "ok: v6 default отсутствует"
  else
    echo "$def6" | grep -q '^unreachable' \
      || fail "v6 default есть и он не unreachable: $def6"
  fi
fi

step "Внутри зоны: DNS по умолчанию 1.1.1.1 (в конфиге нет DNS=)"
resolv=$(in_zone cat /etc/resolv.conf)
echo "$resolv"
echo "$resolv" | grep -Eq '^nameserver[[:space:]]+1\.1\.1\.1' \
  || fail "в /etc/resolv.conf зоны нет nameserver 1.1.1.1"

step "Внутри зоны: маршрут до endpoint (192.0.2.1) идёт В ТУННЕЛЬ"
# Ассерт ПЕРЕВЁРНУТ по сравнению с одно-namespace версией — и это главное
# следствие шлюзовой архитектуры. Раньше в зоне был /32 до VPN-сервера мимо
# туннеля (иначе пакеты туннеля заворачивались бы в туннель) — и приложения его
# видели. Теперь шифрованный трафик рождается в uplink-ns и уходит ЕГО
# маршрутом, а в app-ns никакого исключения нет и быть не должно: петли не
# возникает по построению.
epr=$(in_zone "$IP" route get 192.0.2.1)
echo "$epr"
echo "$epr" | grep -q 'dev awg0' \
  || fail "маршрут до endpoint идёт мимо туннеля — в app-ns остался путь наружу"

step "Внутри аплинка: tap от pasta и default route (диагностика)"
ulinks=$(in_uplink "$IP" -o link show)
echo "$ulinks"
echo "$ulinks" | grep -q ': hostif[:@]' || fail "в uplink-ns нет интерфейса pasta (hostif)"
udef=$(in_uplink "$IP" -4 route show default)
echo "${udef:-<пусто>}"
[ -n "$udef" ] || fail "в uplink-ns нет default route — pasta не настроила выход"
# Туннеля в аплинке быть не должно: он там рождается и сразу переезжает вниз.
if in_uplink "$IP" -o link show awg0 >/dev/null 2>&1; then
  fail "awg0 остался в uplink-ns — переезд интерфейса не состоялся"
fi

# --- 6. Контейнер данных (профиль) через vpn-zone run ------------------------
# Проверяется весь путь запуска: nsenter в зону с --keep-caps, свой mount
# namespace, overlay поверх XDG-каталогов и сброс ambient capabilities — то, что
# делает `vpn-zone-core profile-run` (крейт rust/, модуль profile).
step "vpn-zone profile create $TEST_PROFILE"
"$VPN_ZONE" profile create "$TEST_PROFILE"
[ -d "$PROFILES/$TEST_PROFILE" ] || fail "каталог профиля не создан"

# Нижний слой должен существовать: несуществующий каталог профиль пропускает, и
# запись ушла бы в настоящий дом — то есть тест проверял бы не то.
mkdir -p "$HOME/.config"

step "vpn-zone run smoke --profile $TEST_PROFILE — запись в слой профиля"
# Зона smoke сейчас поднята держателем, поэтому zone_pid её находит и systemctl
# не понадобится. Графики на раннере нет: kdialog-ветки (предупреждение «уже
# запущена в другой сети») не срабатывают, а wl-sandbox без композитора пишет
# предупреждение и запускает команду как есть — оба пути чистые.
"$VPN_ZONE" run smoke --profile "$TEST_PROFILE" -- \
  sh -c 'echo marker > "$HOME/.config/vpn-smoke-marker"'

UPPER="$PROFILES/$TEST_PROFILE/.config/upper/vpn-smoke-marker"
[ -f "$UPPER" ] || fail "маркера нет в верхнем слое ($UPPER) — overlay профиля не наложился"
[ ! -e "$MARKER" ] || fail "маркер попал в настоящий ~/.config — слой профиля не изолировал запись"
echo "ok: запись ушла в слой профиля, настоящий ~/.config не тронут"

step "vpn-zone profile rm $TEST_PROFILE"
"$VPN_ZONE" profile rm "$TEST_PROFILE"
[ ! -d "$PROFILES/$TEST_PROFILE" ] || fail "профиль не удалился"

# --- 7. Offline-зона ---------------------------------------------------------
step "Создаю offline-зону offsmoke (как это делает пикер: mkdir + touch offline)"
mkdir -p "$STATE/offsmoke"
: > "$STATE/offsmoke/offline"
"$ZONE_HOLDER" offsmoke >"$WORK/holder-offsmoke.log" 2>&1 &
HOLDER_PIDS+=("$!")
wait_file "$STATE/offsmoke/ready" 200 || fail "offline-зона не поднялась за 20 секунд"
OPID=$(cat "$STATE/offsmoke/zone.pid")
echo "ok: offline-зона поднята, pid $OPID"

in_off() {
  "$NSENTER" --preserve-credentials -U -n -m -t "$OPID" -- "$@"
}

step "Внутри offline-зоны: только lo, default route отсутствует"
links=$(in_off "$IP" -o link show)
echo "$links"
[ "$(echo "$links" | wc -l)" -eq 1 ] || fail "в offline-зоне есть интерфейсы кроме lo"
echo "$links" | grep -q ': lo:' || fail "в offline-зоне нет даже lo"
offdef=$(in_off "$IP" -4 route show default)
[ -z "$offdef" ] || fail "в offline-зоне есть default route: $offdef"
echo "ok: сети нет физически"

# --- 8. Гасим и проверяем уборку ---------------------------------------------
step "Гашу держателей (TERM) и добиваю процессы зон"
for p in "${HOLDER_PIDS[@]}"; do
  kill -TERM "$p" 2>/dev/null || true
done
sleep 1
for z in "${TEST_ZONES[@]}"; do
  for f in zone.pid uplink.pid; do
    zp=$(cat "$STATE/$z/$f" 2>/dev/null || true)
    if [ -n "$zp" ] && [ -d "/proc/$zp" ]; then
      kill -TERM "$zp" 2>/dev/null || true
    fi
  done
  # то же, что в cleanup: остаток дорустовой версии, шаблон сужен до тестовых
  # зон, чтобы на рабочей машине не задеть настоящие
  pkill -TERM -f "vpn-zone-init $z\$" 2>/dev/null || true
done
HOLDER_PIDS=()

step "Проверяю, что pasta умерла вместе с зоной"
# Ищем ровно НАШУ pasta, а не любую на машине. В шлюзовой архитектуре pasta
# цепляется к АПЛИНКУ, а не к namespace приложений — по этому же номеру её
# находит и `vpn-zone gc` (он читает /proc/N/ns/net из её cmdline).
pasta_pat="pasta --netns /proc/$UPID/ns/net"
for _ in $(seq 1 50); do
  pgrep -f "$pasta_pat" >/dev/null || break
  sleep 0.1
done
if pgrep -af "$pasta_pat"; then
  fail "pasta пережила остановку зоны"
fi
echo "ok: pasta нет"

step "СМОУК ПРОЙДЕН"
