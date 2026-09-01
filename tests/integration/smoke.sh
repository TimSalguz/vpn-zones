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
# ВТОРОЙ ЭШЕЛОН проверяется МЯГКО, и это не халтура. nftables в зоне — страховка
# поверх топологии, а не её основа: держатель, которому ядро не дало создать
# таблицу (нет nf_tables — из непривилегированного userns модуль не
# автозагружается), громко пишет об этом в журнал и поднимает зону дальше.
# Раннер CI может оказаться и таким, и другим, поэтому ассерт различает ровно
# два исхода: либо правила стоят и они те самые, либо предупреждение в журнале
# держателя. Третьего — «правил нет и все молчат» — быть не должно.
#
# Тест использует зоны с именами smoke, smoke-crlf, offsmoke в
# ~/.local/state/vpn-zones, профиль smoketest-prof в ~/.local/state/vpn-profiles,
# набор доступов smoke-fsapp в ~/.config/vpn-zones/fs-perms и память пикера по
# ключу smoke-pickapp (.last/.lastprofile/.labels) — и удаляет их же в начале.
# Настройки пользователя (~/.config/vpn-zones/default и прочие) НЕ трогает: на
# рабочей машине это его настоящая конфигурация.
set -euo pipefail

step() { printf '\n==> %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
HARNESS="$REPO_ROOT/tests/harness.nix"
WORK=$(mktemp -d)
STATE="$HOME/.local/state/vpn-zones"
PROFILES="$HOME/.local/state/vpn-profiles"
TEST_ZONES=(smoke smoke-crlf offsmoke ocsmoke)
TEST_PROFILE=smoketest-prof
MARKER="$HOME/.config/vpn-smoke-marker"
# Песочница файловой системы: свой app-id (набор доступов запоминается по нему)
# и маркер в настоящем доме, которого изнутри песочницы видно быть не должно.
FSAPP=smoke-fsapp
FSPERMS="$HOME/.config/vpn-zones/fs-perms/$FSAPP"
FSMARKER="$HOME/vpn-smoke-fs-marker"
# Синтетический ключ программы для проверки пикера: свои файлы памяти в общем
# каталоге состояния, чужих (настоящих) не касаемся.
PICKKEY=smoke-pickapp
HOLDER_PIDS=()

cleanup() {
  rc=$?
  set +e
  # Сервер OpenConnect (если поднимался) — он под sudo и обычным kill не
  # гасится. Ищем по пути НАШЕГО конфига, чтобы не задеть чужой ocserv.
  if [ -n "${OCSERV_CONF:-}" ]; then
    sudo -n pkill -TERM -f "$OCSERV_CONF" 2>/dev/null
  fi
  # Каталог сервера лежит в /tmp (см. ниже, про nobody и $TMPDIR раннера), а
  # значит его не уносит уборка $WORK.
  [ -n "${OCDIR:-}" ] && rm -rf "${OCDIR:?}"
  # И адрес, который выдавали хосту под сервер.
  if [ -n "${OC_HOST_ADDR:-}" ]; then
    sudo -n ip addr del "$OC_HOST_ADDR/32" dev lo 2>/dev/null
  fi
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
  rm -f "$MARKER" "$FSPERMS" "$FSMARKER"
  # Память пикера по синтетическому ключу — свои файлы, чужих здесь не бывает.
  rm -f "${STATE:?}/.last/$PICKKEY" "${STATE:?}/.lastprofile/$PICKKEY" \
        "${STATE:?}/.labels/$PICKKEY"
  if [ "$rc" -ne 0 ]; then
    for z in smoke offsmoke ocsmoke; do
      if [ -s "$WORK/holder-$z.log" ]; then
        printf -- '--- журнал держателя %s ---\n' "$z"
        cat "$WORK/holder-$z.log"
      fi
    done
    if [ -s "$WORK/ocserv.log" ]; then
      printf -- '--- журнал ocserv ---\n'
      tail -120 "$WORK/ocserv.log"
    fi
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
build scripts.vpn-zone-pick vpn-zone-pick
build zoneHolder zone-holder
build smokeTools tools

VPN_ZONE="$WORK/vpn-zone/bin/vpn-zone"
VPN_ZONE_PICK="$WORK/vpn-zone-pick/bin/vpn-zone-pick"
ZONE_HOLDER="$WORK/zone-holder/bin/zone-holder"
WG="$WORK/tools/bin/wg"
IP="$WORK/tools/bin/ip"
NSENTER="$WORK/tools/bin/nsenter"
UNSHARE="$WORK/tools/bin/unshare"
NFT="$WORK/tools/bin/nft"

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
rm -f "$MARKER" "$FSPERMS" "$FSMARKER"
rm -f "${STATE:?}/.last/$PICKKEY" "${STATE:?}/.lastprofile/$PICKKEY" \
      "${STATE:?}/.labels/$PICKKEY"

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

# То же, но uid 0 ВНУТРИ userns зоны — только для nft. Без --preserve-credentials
# nsenter делает setuid(0)/setgid(0) уже внутри, где ноль — это subuid-«root»
# зоны со всеми capabilities. Под обычным uid они обнуляются на execve
# (docs/GOTCHAS.md §1), а nfnetlink требует CAP_NET_ADMIN даже на ЧТЕНИЕ
# ruleset'а — ровно по этой же причине зона пишет зеркало `awg show` сама изнутри
# (§4). Заодно это и есть свойство второго эшелона: программа, вошедшая в зону
# обычным `vpn-zone run`, правил не то что снять — прочитать не может.
in_zone_root() {
  "$NSENTER" -U -n -m -t "$ZPID" -- "$@"
}
in_uplink_root() {
  "$NSENTER" -U -n -m -t "$UPID" -- "$@"
}

# Второй эшелон: правила стоят и они те самые, ЛИБО ядро раннера не даёт
# nf_tables и держатель честно сказал об этом. Третьего исхода нет.
#
# Мягкость ассерта могла бы спрятать НАШУ ошибку: битый ruleset тоже не
# загрузился бы, тоже дал бы предупреждение — и тест позеленел бы на баге.
# Поэтому «правил нет» разбирается до конца: если заведомо валидная пустая
# таблица в этом же namespace создаётся, значит nf_tables работает и не принят
# был именно наш ruleset — это провал, а не деградация.
check_echelon() { # <входилка-в-namespace> <журнал держателя> <имя> <шаблон>…
  local enter="$1" log="$2" what="$3"
  shift 3
  local err="$WORK/nft-$what.err" probe="$WORK/nft-$what.probe"
  local rules pat
  rules=$("$enter" "$NFT" list ruleset 2>"$err" || true)
  echo "${rules:-<пусто>}"
  if [ -n "$rules" ]; then
    for pat in "$@"; do
      echo "$rules" | grep -Eq "$pat" || fail "$what: в ruleset нет /$pat/"
    done
    echo "ok: $what — правила на месте"
    return 0
  fi
  grep -qi 'second echelon is off' "$log" || {
    printf 'nft сказал: %s\n' "$(cat "$err" 2>/dev/null)" >&2
    fail "$what: правил нет, а держатель о выключенном эшелоне не предупредил"
  }
  if printf 'table inet vpnzoneprobe {}\n' | "$enter" "$NFT" -f - 2>"$probe"; then
    printf 'nft о нашем ruleset: %s\n' "$(cat "$err" 2>/dev/null)" >&2
    fail "$what: пустая таблица создаётся, а наш ruleset не принят — ошибка не в ядре, а у нас"
  fi
  echo "ok (деградация): $what без nf_tables ($(head -1 "$probe")); держит топология"
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

step "Внутри зоны: второй эшелон — output policy drop, выпускать только в awg0"
# Страховка поверх топологии, а не её замена: если однажды в app-ns по ошибке
# появится ещё один интерфейс, трафик в него молча не уйдёт. Правило именно
# oifname (по имени), а не oif (по индексу) — оно грузится ДО приезда туннеля.
check_echelon in_zone_root "$WORK/holder-smoke.log" "app-ns" \
  'chain output' 'policy drop' 'oifname "awg0" accept'

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

step "Внутри аплинка: второй эшелон — наружу только транспорт туннеля"
# Аплинк заперт до одного адреса и одного порта: даже скомпрометированный
# процесс здесь не отправит ничего, кроме пакетов туннеля. DNS и ICMP тут не
# нужны — имя endpoint'а резолвится заранее, в сети хоста. Шаблон без ведущего
# «ip»: нас интересует форма правила, а не то, как nft печатает семейство.
check_echelon in_uplink_root "$WORK/holder-smoke.log" "uplink-ns" \
  'chain output' 'policy drop' 'daddr 192\.0\.2\.1 udp dport 51820 accept'

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
# При провале — владельцы и права всего дерева: без этого EACCES нечитаем.
"$VPN_ZONE" profile rm "$TEST_PROFILE" || {
  ls -lnRa "$PROFILES/$TEST_PROFILE" >&2 || true
  fail "profile rm не смог удалить дерево профиля"
}
[ ! -d "$PROFILES/$TEST_PROFILE" ] || fail "профиль не удалился"

# --- 6б. Песочница файловой системы ------------------------------------------
# Проверяется `vpn-zone-core fs-sandbox` (крейт rust/, модуль fs_sandbox) —
# бывший shell-скрипт vpn-fs-sandbox. Зона тут ни при чём: песочница ФС —
# отдельный слой, и запускается она в обычной сети раннера.
#
# Пути инструментов НЕ собираются отдельно, а достаются из МАНИФЕСТА — того
# самого JSON, на который показывает обёртка vpn-zone (VPN_ZONE_TOOLS). Так тест
# проверяет ровно то, что поедет пользователю, а не свою сборку. Раньше они
# грепались из текста shell-скрипта vpn-zone; скрипта больше нет, есть бинарь и
# двухстрочная обёртка к нему.
step "Песочница ФС: достаю пути инструментов из манифеста собранного vpn-zone"
# «grep -m1 -o», а не «grep -o | head -1»: под set -o pipefail head, закрывший
# трубу первым, обрекает пайплайн на 141, и весь смоук падал бы по случайности
# размера вывода. -m1 останавливает сам grep, а искомых подстрок в первой же
# подходящей строке ровно по одной.
TOOLS=$(grep -m1 -o '/nix/store/[^ "]*-vpn-zone-tools.json' "$VPN_ZONE")
[ -n "$TOOLS" ] && [ -f "$TOOLS" ] || fail "в обёртке vpn-zone нет пути к манифесту инструментов"
# Плоский JSON «ключ: значение» — «|| true» на случай отсутствующего ключа:
# пустое значение поймает общая проверка ниже и скажет, какого именно нет.
tool() {
  grep -m1 -o "\"$1\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$TOOLS" \
    | sed 's/.*:[[:space:]]*"//; s/"$//' || true
}
FSCORE=$(tool core)
FSBWRAP=$(tool bwrap)
FSPROXY=$(tool dbus-proxy)
# Оболочка и coreutils для команды ВНУТРИ песочницы: /usr и /bin туда не
# пробрасываются, поэтому «sh» и «ls» обязаны быть store-путями. Шебанг обёртки
# — это bash, а ls берём из тех же smokeTools, откуда nsenter и ip.
FSSH=$(head -1 "$VPN_ZONE" | sed 's|^#!||')
FSCOREUTILS="$WORK/tools/bin"
for v in FSCORE FSBWRAP FSPROXY FSSH FSCOREUTILS; do
  [ -n "${!v}" ] || fail "не нашёл $v в тексте собранного vpn-zone"
done
[ -x "$FSCORE" ] || fail "vpn-zone-core не исполняемый: $FSCORE"
[ -x "$FSBWRAP" ] || fail "bwrap не исполняемый: $FSBWRAP"
[ -x "$FSCOREUTILS/ls" ] || fail "нет $FSCOREUTILS/ls"
echo "ok: core=$FSCORE"
echo "ok: bwrap=$FSBWRAP"

# Подставной kdialog: без графики диалог доступов не должен вызываться ВООБЩЕ.
# Если вызовется — оставит свидетеля и выдаст «home», то есть тест покраснеет
# сразу двумя проверками. Настоящий kdialog сюда подставлять нельзя: он ждал бы
# ответа, которого на раннере некому дать.
cat > "$WORK/fake-kdialog" <<EOF
#!$FSSH
: > "$WORK/kdialog-was-called"
echo home
EOF
chmod +x "$WORK/fake-kdialog"

step "Песочница ФС: дом пуст, маркер хоста не виден, /nix/store виден"
: > "$FSMARKER"
# Команда внутри самодостаточна: $WORK лежит в /tmp, а /tmp внутри песочницы —
# свежий tmpfs, никакой файл-скрипт оттуда виден не будет. Путь к ls приходит
# позиционным аргументом ($0 занят именем оболочки), а завершающий «exit 0»
# обязателен: последняя проверка отсутствия маркера возвращает 1, и без него
# песочница отдала бы наружу код 1.
fsout=$(env -u WAYLAND_DISPLAY -u DISPLAY "$FSCORE" fs-sandbox \
  --bwrap "$FSBWRAP" --dbus-proxy "$FSPROXY" \
  --kdialog "$WORK/fake-kdialog" --xwayland /nonexistent/xwayland-satellite \
  "$FSAPP" -- "$FSSH" -c '
    "$1" -A "$HOME" | while read -r f; do echo "SEEN:$f"; done
    [ -d /nix/store ] && echo STORE-OK
    [ -e "$HOME/vpn-smoke-fs-marker" ] && echo LEAK
    exit 0
  ' sh "$FSCOREUTILS/ls") || fail "песочница не запустилась (см. вывод выше)"
echo "${fsout:-<пусто>}"
echo "$fsout" | grep -q '^STORE-OK$' || fail "внутри песочницы не виден /nix/store"
if echo "$fsout" | grep -q '^LEAK$'; then
  fail "маркер настоящего дома виден изнутри песочницы"
fi
if echo "$fsout" | grep -q '^SEEN:'; then
  fail "дом внутри песочницы не пуст"
fi
[ -e "$FSMARKER" ] || fail "маркер пропал из настоящего дома"
echo "ok: дом внутри пуст, наружу не видно ничего"

step "Песочница ФС: доступы записаны пустыми, диалог не показывался"
[ -f "$FSPERMS" ] || fail "файл доступов $FSPERMS не создан"
[ ! -s "$FSPERMS" ] || fail "без графики доступов быть не должно, а там: $(cat "$FSPERMS")"
[ ! -e "$WORK/kdialog-was-called" ] || fail "без графики был вызван kdialog — программа зависла бы"
echo "ok: доступы пусты, kdialog не звался"

# Мягкая деградация шины: раньше сокет недоступного прокси биндился безусловно,
# bwrap падал на «Can't find source path», и программа не открывалась вовсе.
step "Песочница ФС: недоступный dbus-прокси не мешает запуску, код выхода — программы"
fsrc=0
env -u WAYLAND_DISPLAY -u DISPLAY "$FSCORE" fs-sandbox \
  --bwrap "$FSBWRAP" --dbus-proxy /nonexistent/xdg-dbus-proxy \
  --kdialog "$WORK/fake-kdialog" --xwayland /nonexistent/xwayland-satellite \
  "$FSAPP" -- "$FSSH" -c 'exit 42' || fsrc=$?
[ "$fsrc" -eq 42 ] || fail "ожидался код выхода программы (42), получен $fsrc"
[ ! -e "$WORK/kdialog-was-called" ] || fail "kdialog вызвался при готовом файле доступов"
echo "ok: без шины запуск живёт, код выхода 42 донесён"

# --- 6в. Пикер сети без графики ----------------------------------------------
# Пикер интерактивен, и проверять здесь можно ровно одно: ветку «спросить
# негде». Она не косметическая — это недавний фикс: без графики kdialog падает
# сразу, а «|| exit 0» принимал это за отмену, и запуск из терминала или из
# юнита тихо заканчивался ничем. Теперь берётся то, что было бы выделено в
# меню (прошлый выбор, иначе общий дефолт), и об этом говорится в stderr.
#
# ПОЧЕМУ ИМЕННО direct, А НЕ offline. Ветка offline поднимает зону через
# `systemctl --user`, которого на раннере нет вовсе (сессионного systemd в
# контейнере CI не бывает) — тест падал бы не по делу. При выборе direct пикер
# НИЧЕГО не поднимает и не зовёт `vpn-zone run`: он становится самой командой
# (exec), потому что «прямой интернет» — это отсутствие зоны. Ассерт получается
# точный и ни от чего не зависящий.
#
# Выбор задаётся файлом памяти .last у синтетического ключа, а не командой
# `vpn-zone default`: смоук гоняют и на рабочей машине, а `default` — настоящая
# настройка пользователя, её трогать нельзя. Файл памяти на своём ключе — нет.
step "Пикер без графики: берёт прошлый выбор и исполняет команду сама"
mkdir -p "$STATE/.last"
printf '%s' direct > "$STATE/.last/$PICKKEY"
pickout=$(env -u WAYLAND_DISPLAY -u DISPLAY -u VPN_ZONE_ASK -u VPN_ZONE_PROFILE \
  -u VPN_ZONE_CURRENT "$VPN_ZONE_PICK" --label "Смоук-программа" --id "$PICKKEY" \
  -- sh -c 'echo ПИКЕР-ЗАПУСТИЛ' 2>"$WORK/pick.err") \
  || fail "пикер без графики завершился с ошибкой (см. $WORK/pick.err)"
echo "${pickout:-<пусто>}"
[ "$pickout" = "ПИКЕР-ЗАПУСТИЛ" ] || fail "пикер не исполнил команду: $pickout"
grep -q 'спросить негде' "$WORK/pick.err" \
  || fail "пикер не сказал, что спрашивать негде: $(cat "$WORK/pick.err")"
# Метку он обязан записать: из неё берутся имена программ в диалогах и в
# списке сброса закреплений (там иначе виден ключ ярлыка).
[ "$(cat "$STATE/.labels/$PICKKEY" 2>/dev/null)" = "Смоук-программа" ] \
  || fail "пикер не записал метку в $STATE/.labels/$PICKKEY"
echo "ok: без графики выбран direct, команда исполнена, метка записана"

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
in_off_root() {
  "$NSENTER" -U -n -m -t "$OPID" -- "$@"
}

step "Внутри offline-зоны: только lo, default route отсутствует"
links=$(in_off "$IP" -o link show)
echo "$links"
[ "$(echo "$links" | wc -l)" -eq 1 ] || fail "в offline-зоне есть интерфейсы кроме lo"
echo "$links" | grep -q ': lo:' || fail "в offline-зоне нет даже lo"
offdef=$(in_off "$IP" -4 route show default)
[ -z "$offdef" ] || fail "в offline-зоне есть default route: $offdef"
echo "ok: сети нет физически"

step "Внутри offline-зоны: правил нет — запрещать нечего"
# Второй эшелон сюда не ставится сознательно: интерфейсов, кроме lo, здесь не
# будет никогда, и правило про них не сказало бы ничего нового.
offrules=$(in_off_root "$NFT" list ruleset 2>/dev/null || true)
[ -z "$offrules" ] || fail "в offline-зоне появился ruleset: $offrules"
echo "ok: ruleset пуст"

# --- 7б. Зона OpenConnect ----------------------------------------------------
# ВТОРОЙ ТИП БЭКЕНДА (rust/src/openconnect.rs). Проверяется весь контур целиком:
# настоящий ocserv на раннере, настоящий openconnect в uplink-ns зоны, его tun
# переезжает в app-ns, и в app-ns снова обязано быть РОВНО два интерфейса.
#
# Почему сервер живёт в сети ХОСТА, а не в отдельном userns: ocserv'у нужен свой
# tun и привилегии, а внутри непривилегированного userns он их не получит —
# зато зоне до него ходить незачем иначе, чем через pasta, то есть ровно тем
# путём, которым она ходит к настоящему шлюзу. Со стороны зоны это неотличимо
# от корпоративного сервера в интернете.
#
# Сертификат и пароль синтетические и генерируются на лету: в git не попадает
# ни ключ, ни отпечаток.
step "Зона OpenConnect: поднимаю ocserv на раннере"
OC_SKIP=""
if ! command -v sudo >/dev/null || ! sudo -n true 2>/dev/null; then
  OC_SKIP="нет sudo без пароля — ocserv не поднять"
fi
if [ -n "$OC_SKIP" ] && [ -n "${VPN_ZONE_SMOKE_REQUIRE_OC:-}" ]; then
  fail "VPN_ZONE_SMOKE_REQUIRE_OC=1, но часть про OpenConnect пропускается: $OC_SKIP"
fi

if [ -n "$OC_SKIP" ]; then
  echo "ПРОПУСК (OpenConnect): $OC_SKIP"
else
  build ocTools octools
  OCSERV="$WORK/octools/bin/ocserv"
  OPENCONNECT="$WORK/octools/bin/openconnect"
  OPENSSL="$WORK/octools/bin/openssl"
  for b in "$OCSERV" "$OPENCONNECT" "$OPENSSL"; do
    [ -x "$b" ] || fail "нет $b"
  done

  # Каталог сервера — В /tmp, а НЕ в $WORK, и это не мелочь. ocserv форкает
  # воркеры под nobody, и каждый из них открывает socket-file, сертификат и
  # файл паролей САМ. $WORK лежит внутри $TMPDIR раннера
  # (/home/runner/work/_temp), а туда nobody не пройдёт ни при каких правах на
  # сам каталог — воркер молча умирает, и клиент видит только «TLS connection
  # was non-properly terminated». /tmp проходим всегда.
  OCDIR=$(mktemp -d /tmp/vpn-zones-ocserv.XXXXXX)
  OCSERV_CONF="$OCDIR/ocserv.conf"
  OCPASS="$WORK/ocsmoke.pass"          # файл пароля зоны: обязан быть 0600
  OCPASSWORD=smoke-secret
  chmod 755 "$OCDIR"

  # АДРЕС СЕРВЕРА — ОТДЕЛЬНЫЙ, а не «адрес раннера», и это важная грабля.
  # pasta КОПИРУЕТ адрес хоста в namespace: у аплинка на hostif ровно тот же
  # 10.x.x.x, что у раннера на eth0. Значит соединение из зоны на «адрес
  # хоста» уходит не наружу, а в собственный стек namespace — и получает
  # Connection refused (проверено в CI). Поэтому серверу выдаётся свой адрес
  # из TEST-NET-1 на lo хоста: в namespace такого адреса нет, пакет уходит
  # маршрутом по умолчанию в pasta, а pasta открывает соединение уже в сети
  # хоста, где адрес локальный. Со стороны зоны это неотличимо от сервера в
  # интернете — что и требуется.
  SRVIP=192.0.2.10
  sudo -n "$IP" addr add "$SRVIP/32" dev lo 2>/dev/null || true
  "$IP" -4 -o addr show dev lo | grep -q "$SRVIP" \
    || fail "не удалось выдать хосту адрес $SRVIP для ocserv"
  OC_HOST_ADDR="$SRVIP"
  echo "ocserv будет слушать на $SRVIP:4443 (адрес на lo хоста)"

  step "Зона OpenConnect: синтетический сертификат и пароль"
  "$OPENSSL" req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj "/CN=vpn-smoke.invalid" -addext "subjectAltName=IP:$SRVIP" \
    -keyout "$OCDIR/key.pem" -out "$OCDIR/cert.pem" >/dev/null 2>&1 \
    || fail "не сгенерировался сертификат"
  # Формат plain-файла ocserv: имя:группы:crypt(3). openssl passwd -6 даёт
  # ровно такой хеш ($6$…), какой понимает crypt(3) glibc.
  ochash=$("$OPENSSL" passwd -6 "$OCPASSWORD")
  printf 'smoke:*:%s\n' "$ochash" > "$OCDIR/passwd"
  printf '%s' "$OCPASSWORD" > "$OCPASS"
  chmod 600 "$OCPASS"

  cat > "$OCSERV_CONF" <<EOF
auth = "plain[passwd=$OCDIR/passwd]"
tcp-port = 4443
udp-port = 4443
run-as-user = nobody
run-as-group = nogroup
socket-file = $OCDIR/socket
server-cert = $OCDIR/cert.pem
server-key = $OCDIR/key.pem
isolate-workers = false
max-clients = 4
max-same-clients = 2
try-mtu-discovery = false
device = ocsmoketun
predictable-ips = true
ipv4-network = 192.168.222.0
ipv4-netmask = 255.255.255.0
dns = 192.168.222.1
default-domain = smoke.example
ping-leases = false
cisco-client-compat = true
dtls-legacy = true
auth-timeout = 40
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT"
pid-file = $OCDIR/ocserv.pid
EOF
  chmod -R a+rX "$OCDIR"

  # shellcheck disable=SC2024
  # Перенаправление делает НАШ шелл, а не sudo, — и это ровно то, что нужно:
  # журнал сервера обязан лечь в $WORK от имени раннера, иначе его потом не
  # прочитать и не удалить.
  sudo -n "$OCSERV" -c "$OCSERV_CONF" -f -d 3 >"$WORK/ocserv.log" 2>&1 &
  for _ in $(seq 1 100); do
    if (exec 3<>"/dev/tcp/$SRVIP/4443") 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  (exec 3<>"/dev/tcp/$SRVIP/4443") 2>/dev/null \
    || { tail -30 "$WORK/ocserv.log" >&2; fail "ocserv не начал слушать $SRVIP:4443"; }
  echo "ok: ocserv слушает"

  # Отпечаток спрашиваем У САМОГО КЛИЕНТА: он печатает готовую строку
  # «--servercert pin-sha256:…» — считать её своими руками значит однажды
  # разойтись с ним в формате. Клиент при этом обязан ОТКАЗАТЬСЯ соединяться:
  # сертификат самоподписанный, а отключать проверку мы не умеем нигде.
  step "Зона OpenConnect: спрашиваю у openconnect отпечаток сертификата"
  ocprobe=$("$OPENCONNECT" --non-inter --protocol=anyconnect "$SRVIP:4443" \
    </dev/null 2>&1 || true)
  OCPIN=$(printf '%s\n' "$ocprobe" | grep -m1 -o 'pin-sha256:[A-Za-z0-9+/=]*' || true)
  if [ -z "$OCPIN" ]; then
    printf '%s\n' "$ocprobe" >&2
    printf -- '--- журнал ocserv ---\n' >&2
    cat "$WORK/ocserv.log" >&2
    fail "openconnect не назвал отпечаток"
  fi
  echo "ok: $OCPIN"

  step "vpn-zone add ocsmoke (конфиг с секцией [OpenConnect])"
  cat > "$WORK/ocsmoke.conf" <<EOF
[OpenConnect]
Server = $SRVIP:4443
Protocol = anyconnect
User = smoke
ServerCert = $OCPIN
PasswordFile = $OCPASS
Args = --no-dtls
EOF
  "$VPN_ZONE" add ocsmoke "$WORK/ocsmoke.conf"
  [ -f "$STATE/ocsmoke/config.conf" ] || fail "конфиг OpenConnect-зоны не скопирован"

  # Тот же файл с запрещённым флагом обязан быть отвергнут ещё на add:
  # белый список Args — это не украшение, а единственное, что мешает подменить
  # --script и вывести туннель из-под стены.
  sed 's/^Args = .*/Args = --script=\/bin\/true/' "$WORK/ocsmoke.conf" > "$WORK/ocbad.conf"
  if "$VPN_ZONE" add ocbadsmoke "$WORK/ocbad.conf" >"$WORK/ocbad.out" 2>&1; then
    rm -rf "${STATE:?}/ocbadsmoke"
    fail "add принял конфиг с --script в Args"
  fi
  rm -rf "${STATE:?}/ocbadsmoke"
  grep -qi 'not allowed' "$WORK/ocbad.out" \
    || fail "add отверг --script, но не объяснил почему: $(cat "$WORK/ocbad.out")"
  echo "ok: --script в Args отвергнут на add"

  step "Поднимаю зону ocsmoke держателем"
  "$ZONE_HOLDER" ocsmoke >"$WORK/holder-ocsmoke.log" 2>&1 &
  HOLDER_PIDS+=("$!")
  wait_file "$STATE/ocsmoke/ready" 600 || fail "зона ocsmoke не поднялась за 60 секунд"
  OCZPID=$(cat "$STATE/ocsmoke/zone.pid")
  OCUPID=$(cat "$STATE/ocsmoke/uplink.pid")
  echo "ok: app-ns pid $OCZPID, uplink pid $OCUPID"

  in_oc() {
    "$NSENTER" --preserve-credentials -U -n -m -t "$OCZPID" -- "$@"
  }
  in_ocup() {
    "$NSENTER" --preserve-credentials -U -n -m -t "$OCUPID" -- "$@"
  }
  in_ocup_root() {
    "$NSENTER" -U -n -m -t "$OCUPID" -- "$@"
  }

  step "Зона OpenConnect: в app-ns РОВНО два линка — lo и awg0"
  # Тот же главный ассерт, что у WireGuard-зоны, и по той же причине: туннель
  # строит чужая программа, а свойство обязано остаться прежним.
  oclinks=$(in_oc "$IP" -o link show)
  echo "$oclinks"
  [ "$(echo "$oclinks" | wc -l)" -eq 2 ] || fail "в app-ns не два интерфейса"
  echo "$oclinks" | grep -q ': lo:' || fail "в app-ns нет lo"
  echo "$oclinks" | grep -q ': awg0[:@]' || fail "в app-ns нет awg0"
  echo "$oclinks" | grep -q 'awg0.*[<,]UP[,>]' || fail "awg0 не поднят"

  step "Зона OpenConnect: default через awg0, адрес от шлюза"
  ocdef=$(in_oc "$IP" -4 route show default)
  echo "$ocdef"
  echo "$ocdef" | grep -q 'dev awg0' || fail "default route не через awg0"
  ocaddr=$(in_oc "$IP" -br -4 addr show awg0)
  echo "$ocaddr"
  echo "$ocaddr" | grep -q '192\.168\.222\.' || fail "адрес не из пула ocserv: $ocaddr"

  step "Зона OpenConnect: маршрут до самого шлюза тоже идёт В ТУННЕЛЬ"
  # То же перевёрнутое условие, что у WireGuard-зоны: исключений в app-ns нет
  # вовсе, TLS-сессия живёт этажом выше.
  ocgw=$(in_oc "$IP" route get "$SRVIP")
  echo "$ocgw"
  echo "$ocgw" | grep -q 'dev awg0' || fail "в app-ns остался путь до шлюза мимо туннеля"

  step "Зона OpenConnect: DNS и search — от шлюза, а не от хоста"
  ocresolv=$(in_oc cat /etc/resolv.conf)
  echo "$ocresolv"
  echo "$ocresolv" | grep -Eq '^nameserver[[:space:]]+192\.168\.222\.1' \
    || fail "в resolv.conf зоны нет резолвера шлюза"
  echo "$ocresolv" | grep -Eq '^search[[:space:]]+smoke\.example' \
    || fail "в resolv.conf зоны нет search-домена шлюза"

  step "Зона OpenConnect: IPv6 без пути наружу"
  if in_oc test -e /proc/sys/net/ipv6; then
    ocdef6=$(in_oc "$IP" -6 route show default 2>/dev/null || true)
    echo "v6 default: ${ocdef6:-<пусто>}"
    if [ -n "$ocdef6" ]; then
      echo "$ocdef6" | grep -q '^unreachable' || fail "v6 default есть и он не unreachable"
    fi
  fi

  step "Зона OpenConnect: в uplink-ns есть pasta, но НЕТ туннеля"
  ocup=$(in_ocup "$IP" -o link show)
  echo "$ocup"
  echo "$ocup" | grep -q ': hostif[:@]' || fail "в uplink-ns нет интерфейса pasta"
  if in_ocup "$IP" -o link show awg0 >/dev/null 2>&1; then
    fail "awg0 остался в uplink-ns — переезд tun не состоялся"
  fi

  step "Зона OpenConnect: второй эшелон аплинка — только адрес шлюза"
  # Правило без порта, и это единственное место, где бэкенд шире WireGuard'а:
  # DTLS уходит на порт, который выбирает сервер. «Только этот шлюз» — то же.
  check_echelon in_ocup_root "$WORK/holder-ocsmoke.log" "uplink-ns (oc)" \
    'chain output' 'policy drop' "daddr ${SRVIP//./\\.} accept"

  step "Зона OpenConnect: трафик реально идёт в туннель"
  # Конец туннеля на стороне сервера — 192.168.222.1, там же слушает сам
  # ocserv. Если TCP-соединение оттуда открывается, значит пакеты прошли весь
  # путь: app-ns → tun → openconnect в uplink-ns → pasta → ocserv.
  in_oc timeout 10 bash -c "exec 3<>/dev/tcp/192.168.222.1/4443" \
    || fail "из зоны не достучаться до конца туннеля — трафик через туннель не идёт"
  echo "ok: соединение через туннель открылось"

  step "Зона OpenConnect: зеркало состояния и vpn-zone check"
  wait_file "$STATE/ocsmoke/status" 100 || fail "зеркало состояния не появилось"
  ocstatus=$(cat "$STATE/ocsmoke/status")
  echo "$ocstatus"
  echo "$ocstatus" | grep -q 'backend: openconnect' || fail "в зеркале нет строки о бэкенде"
  echo "$ocstatus" | grep -q 'connected: yes' || fail "в зеркале нет connected: yes"
  "$VPN_ZONE" check ocsmoke || fail "vpn-zone check не признал OpenConnect-зону живой"

  step "Зона OpenConnect: смерть клиента валит зону"
  # Fail-closed: клиента убиваем, и зона обязана уйти целиком — держатель
  # видит смерть аплинка и гасит всё. Убить его можно только став root ВНУТРИ
  # userns зоны: настоящий uid процесса — это subuid, и обычным kill он не
  # достаётся (docs/GOTCHAS.md §1).
  OCPID=$(pgrep -f 'openconnect --protocol=anyconnect' | head -1 || true)
  [ -n "$OCPID" ] || fail "процесс openconnect не найден"
  "$NSENTER" -U -t "$OCUPID" -- kill -TERM "$OCPID" || fail "не убить openconnect"
  ocgone=""
  for _ in $(seq 1 100); do
    if [ ! -d "/proc/$OCZPID" ] && [ ! -d "/proc/$OCUPID" ]; then
      ocgone=1
      break
    fi
    sleep 0.1
  done
  [ -n "$ocgone" ] || fail "клиент убит, а namespace зоны живы — зона не fail-closed"
  echo "ok: зона ушла вместе с клиентом"

  sudo -n pkill -TERM -f "$OCSERV_CONF" 2>/dev/null || true
fi

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
