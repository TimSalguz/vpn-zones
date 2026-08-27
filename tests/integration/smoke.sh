#!/usr/bin/env bash
# Смоук-тест vpn-zones: поднимает настоящую зону в непривилегированном userns
# и проверяет её изнутри. Работает без systemd --user юнита: держатель зоны
# запускается напрямую (атрибут zoneHolder из tests/harness.nix).
#
# РАСЧЁТ НА FALLBACK: на CI-раннере нет модуля amneziawg, поэтому тест
# предполагает, что zone-init при неудаче `ip link add … type amneziawg` и
# конфиге БЕЗ параметров обфускации (Jc/S1/S2/H1-4/I1-5) поднимает ядерный
# wireguard (утилитой wg) на том же имени интерфейса awg0.
#
# Endpoint — 192.0.2.1 (TEST-NET-1, недостижим): рукопожатие для смоука не
# нужно, проверяется сама механика зоны, а не живость сервера.
#
# Тест использует зоны с именами smoke, smoke-crlf, offsmoke в
# ~/.local/state/vpn-zones и удаляет их же в начале.
set -euo pipefail

step() { printf '\n==> %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
HARNESS="$REPO_ROOT/tests/harness.nix"
WORK=$(mktemp -d)
STATE="$HOME/.local/state/vpn-zones"
TEST_ZONES=(smoke smoke-crlf offsmoke)
HOLDER_PIDS=()

cleanup() {
  rc=$?
  set +e
  for p in "${HOLDER_PIDS[@]}"; do kill -TERM "$p" 2>/dev/null; done
  for z in "${TEST_ZONES[@]}"; do
    zp=$(cat "$STATE/$z/zone.pid" 2>/dev/null)
    [ -n "$zp" ] && kill -TERM "$zp" 2>/dev/null
  done
  # zone-init и его фоновый цикл статуса юниту тут не подчинены (в проде их
  # добивает KillMode=control-group) — добиваем сами. Шаблон сужен до ИМЁН
  # ТЕСТОВЫХ зон: голый «vpn-zone-init» убил бы и настоящие зоны, если смоук
  # гоняют на рабочей машине.
  for z in "${TEST_ZONES[@]}"; do
    pkill -TERM -f "vpn-zone-init $z\$" 2>/dev/null
  done
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
echo "ok: зона smoke поднята, pid $ZPID"

in_zone() {
  "$NSENTER" --preserve-credentials -U -n -m -t "$ZPID" -- "$@"
}

# --- 5. Проверки внутри зоны -------------------------------------------------
step "Внутри зоны: интерфейс awg0 существует и UP"
linkline=$(in_zone "$IP" -o link show awg0) || fail "внутри зоны нет интерфейса awg0"
echo "$linkline"
echo "$linkline" | grep -q '[<,]UP[,>]' || fail "awg0 не поднят (нет флага UP)"

step "Внутри зоны: v4 default route через awg0"
def4=$(in_zone "$IP" -4 route show default)
echo "${def4:-<пусто>}"
echo "$def4" | grep -q 'dev awg0' || fail "default route не через awg0"

step "Внутри зоны: IPv6 закрыт (конфиг без v6)"
if ! in_zone test -e /proc/sys/net/ipv6; then
  echo "ok: IPv6 в ядре нет"
else
  d6=$(in_zone cat /proc/sys/net/ipv6/conf/all/disable_ipv6)
  if [ "$d6" = "1" ]; then
    echo "ok: disable_ipv6 = 1"
  else
    def6=$(in_zone "$IP" -6 route show default 2>/dev/null || true)
    echo "disable_ipv6=$d6; v6 default: ${def6:-<пусто>}"
    echo "$def6" | grep -q '^unreachable' \
      || fail "IPv6 не выключен и v6 default не unreachable — утечка мимо туннеля"
  fi
fi

step "Внутри зоны: DNS по умолчанию 1.1.1.1 (в конфиге нет DNS=)"
resolv=$(in_zone cat /etc/resolv.conf)
echo "$resolv"
echo "$resolv" | grep -Eq '^nameserver[[:space:]]+1\.1\.1\.1' \
  || fail "в /etc/resolv.conf зоны нет nameserver 1.1.1.1"

step "Внутри зоны: маршрут до endpoint (192.0.2.1) идёт МИМО awg0"
epr=$(in_zone "$IP" route get 192.0.2.1)
echo "$epr"
if echo "$epr" | grep -q 'dev awg0'; then
  fail "маршрут до endpoint завёрнут в туннель — петля"
fi

# --- 6. Offline-зона ---------------------------------------------------------
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

# --- 7. Гасим и проверяем уборку ---------------------------------------------
step "Гашу держателей (TERM) и добиваю процессы зон"
for p in "${HOLDER_PIDS[@]}"; do
  kill -TERM "$p" 2>/dev/null || true
done
sleep 1
for z in "${TEST_ZONES[@]}"; do
  zp=$(cat "$STATE/$z/zone.pid" 2>/dev/null || true)
  if [ -n "$zp" ] && [ -d "/proc/$zp" ]; then
    kill -TERM "$zp" 2>/dev/null || true
  fi
  # фоновый цикл статуса zone-init; шаблон сужен до тестовых зон, чтобы на
  # рабочей машине не задеть настоящие
  pkill -TERM -f "vpn-zone-init $z\$" 2>/dev/null || true
done
HOLDER_PIDS=()

step "Проверяю, что pasta умерла вместе с зоной"
# Ищем ровно НАШУ pasta (по netns тестовой зоны), а не любую на машине.
pasta_pat="pasta --netns /proc/$ZPID/ns/net"
for _ in $(seq 1 50); do
  pgrep -f "$pasta_pat" >/dev/null || break
  sleep 0.1
done
if pgrep -af "$pasta_pat"; then
  fail "pasta пережила остановку зоны"
fi
echo "ok: pasta нет"

step "СМОУК ПРОЙДЕН"
