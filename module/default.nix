# VPN-ЗОНЫ: сетевые «контейнеры» с VPN, создаваемые и управляемые ИЗ-ПОД ПОЛЬЗОВАТЕЛЯ.
#
# ЧТО ЭТО ДАЁТ. Зона — это отдельное сетевое пространство с поднятым в нём
# туннелем. Приложение, запущенное «в зоне», ходит в сеть только через её VPN;
# всё остальное на машине этого не замечает. Зон может быть сколько угодно и
# каждая со своим конфигом: «Chromium (nl)», «Telegram (ru)» — параллельно.
#
# ЧЕМ ОТЛИЧАЕТСЯ ОТ ОБЫЧНЫХ ОБВЯЗОК НАД netns. Те требуют root и знают ровно один
# namespace, прописанный в системной конфигурации. Здесь root не
# нужен нигде: ни на создание зоны, ни на запуск. Добавление нового VPN — это не
# пересборка системы, а ярлык в лаунчере и файлпикер.
#
# ПОЧЕМУ ЭТО ВООБЩЕ ВОЗМОЖНО БЕЗ ROOT (проверено на niri и KWin):
#   • непривилегированные user namespace разрешены ядром;
#   • /etc/subuid выдаёт пользователю диапазон дополнительных uid — из него берётся «root»
#     внутри зоны, и newuidmap имеет на это cap_setuid;
#   • ядерный модуль amneziawg разрешает создавать интерфейс внутри такого
#     namespace — то есть туннель настоящий, не userspace-эмуляция;
#   • выход зоны наружу даёт pasta (passt) — пользовательский сетевой стек,
#     тот же, на котором работает rootless-podman.
#
# УСТРОЙСТВО (ключевой момент — двойной маппинг uid):
#   unshare --map-users=0:<subuid>:1 --map-users=<uid>:<uid>:1 --setuid 0
#     ├── дочерний net+mount namespace ─ ЗОНА: здесь awg0, маршруты, свой resolv.conf
#     └── pasta --netns <зона> ─ выход в интернет
# Внутри мы uid 0 — иначе ядро не даст создать интерфейс (capabilities теряются
# при execve, если uid не нулевой; проверено, с identity-маппингом CapEff=0).
# Но uid пользователя отображён ВТОРЫМ диапазоном, поэтому приложение, вошедшее в
# зону через nsenter --preserve-credentials, работает под твоим настоящим uid и
# видит $HOME как обычно. Ровно то же делает podman в режиме keep-id.
#
# КАК ЭТО ВЫГЛЯДИТ В ЛАУНЧЕРЕ. По умолчанию (режим picker) ярлык у программы
# остаётся ОДИН, но при запуске спрашивает, в какой сети её пустить: прямой
# интернет, без сети, или любая из зон. Выбранное запоминается, а пунктом
# «Всегда: …» закрепляется навсегда — тогда диалога больше не будет. Сбросить
# закрепление можно ярлыком «Сбросить сети программ» (у одной программы или у
# всех) либо командой `vpn-zone forget`.
#
# Незнакомая программа по умолчанию предлагает вариант «Без сети» — это и есть
# политика «интернет не выдаётся, пока его явно не дали». Поменять:
# `vpn-zone default direct`. Кому больше нравится прежний вид — «Firefox (nl)»
# отдельным ярлыком на каждую зону — включается `vpn-zone mode per-zone`
# (или both, чтобы работало и то, и другое).
#
# ЧЕГО ЭТО НЕ ДЕЛАЕТ. Зона изолирует ТОЛЬКО сеть. Файловая система, буфер обмена,
# композитор, dbus — общие с хостом. Для недоверенных программ нужен ещё
# контейнер ФС и вложенный композитор — это следующий слой, здесь его нет.
#
# ГРАБЛЯ, О КОТОРОЙ НАДО ПОМНИТЬ ПРИ СОЗДАНИИ ЗОН. Один и тот же приватный ключ
# нельзя держать поднятым дважды: сервер помнит для ключа ровно один endpoint, и
# второе соединение перебивает первое — оба начинают рваться. Поэтому НЕ поднимай
# зону из того же конфига, который уже поднят системным туннелем, и не используй
# один файл для двух зон. Нужны параллельные зоны —
# нужны разные ключи (в Amnezia это отдельная конфигурация на каждое устройство).
{
  config,
  lib,
  pkgs,
  ...
}:

let
  stateDir = "${config.home.homeDirectory}/.local/state/vpn-zones";
  # Профили (контейнеры данных) намеренно вне каталога зон: зону можно удалить,
  # когда VPN заблокировали, а настроенное в профиле окружение должно пережить
  # это и открыться в другой сети.
  #
  # Путь именно в .local/state, и это НЕ вкусовщина. Профиль накрывает своим
  # слоем .config, .local/share, .cache, .mozilla, .pki — а верхний слой
  # overlayfs не может находиться на overlayfs. Пока хранилище лежало в
  # .local/share, первые два каталога монтировались, а на .cache и дальше ядро
  # отвечало EINVAL: их upperdir оказывался уже накрыт предыдущим слоем.
  # .local/state в этот список не входит, поэтому конфликта нет.
  profilesDir = "${config.home.homeDirectory}/.local/state/vpn-profiles";

  # Инструменты, к которым обращаются скрипты. Абсолютные пути, потому что часть
  # кода исполняется внутри namespace, где PATH может быть каким угодно.
  iproute = "${pkgs.iproute2}/bin/ip";
  awg = "${pkgs.amneziawg-tools}/bin/awg";
  wg = "${pkgs.wireguard-tools}/bin/wg";
  pasta = "${pkgs.passt}/bin/pasta";
  notify = "${pkgs.libnotify}/bin/notify-send";
  kdialog = "${pkgs.kdePackages.kdialog}/bin/kdialog";

  # --- ЧАСТЬ 0: ОГРАНИЧЕНИЕ ДОСТУПА К КОМПОЗИТОРУ ---
  # Собираем маленькую программу на C (готовой утилиты в nixpkgs нет). Она
  # создаёт помеченный wayland-сокет, после чего композитор перестаёт выдавать
  # клиенту протоколы слежки — подробности в самом wl-sandbox.c.
  wl-sandbox = pkgs.stdenv.mkDerivation {
    pname = "wl-sandbox";
    version = "1";
    src = ./wl-sandbox.c;
    dontUnpack = true;
    nativeBuildInputs = [ pkgs.wayland-scanner pkgs.pkg-config ];
    buildInputs = [ pkgs.wayland ];
    buildPhase = ''
      proto=${pkgs.wayland-protocols}/share/wayland-protocols/staging/security-context/security-context-v1.xml
      wayland-scanner client-header "$proto" security-context-v1-client-protocol.h
      wayland-scanner private-code  "$proto" security-context-v1-protocol.c
      # Копия рядом с генерёнными заголовками: #include "…" ищет их относительно
      # исходника, а тот лежит в /nix/store, где ничего сгенерировать нельзя.
      cp $src wl-sandbox.c
      $CC -O2 -Wall -I. -o wl-sandbox wl-sandbox.c security-context-v1-protocol.c \
        $(pkg-config --cflags --libs wayland-client)
    '';
    installPhase = ''
      install -Dm755 wl-sandbox $out/bin/wl-sandbox
    '';
  };

  # --- ЧАСТЬ 0б: RUST-ЯДРО ---
  # Отсюда идёт переезд ядра на Rust (ROADMAP M1/M2). Первым переехало то, чего
  # в bash нет в принципе: BPF-фильтр системных вызовов для песочницы —
  # программу для ядра умеет собрать только код (libseccomp). Следом переехали
  # оба бывших python-скрипта: наложение слоёв профиля при запуске программы и
  # генератор .desktop-ярлыков. Python в проекте больше нет.
  #
  # В крейте лежит ещё парсер конфигов WG/AWG с тестами на все грабли из
  # docs/GOTCHAS.md §4, но зоны его пока не используют: bash-версия остаётся
  # рабочей до подтверждённого паритета.
  #
  # Два бинаря: vpn-zone-seccomp (фильтр) и vpn-zone-core (подкоманды
  # profile-run и sync). Со скриптом vpn-zone имена не сталкиваются — всё
  # спокойно лежит в home.packages.
  vpn-zone-rust = pkgs.rustPlatform.buildRustPackage {
    pname = "vpn-zone-rust";
    version = "0.1.0";
    # Крейт — сосед модуля в репозитории, а не его часть: ../rust от
    # module/default.nix. В store кладём только исходники: попади туда ещё и
    # target/ (появляется, стоит один раз запустить cargo руками), каждая
    # пересборка тащила бы в store гигабайты и меняла хеш деривации.
    src = lib.fileset.toSource {
      root = ../rust;
      fileset = lib.fileset.unions [
        ../rust/Cargo.toml
        ../rust/Cargo.lock
        ../rust/src
        ../rust/tests
      ];
    };
    cargoLock.lockFile = ../rust/Cargo.lock;
    # libseccomp-sys линкуется с системной libseccomp, а её версию ищет
    # pkg-config (build.rs крейта libseccomp).
    nativeBuildInputs = [ pkgs.pkg-config ];
    buildInputs = [ pkgs.libseccomp ];
    # Тесты гоняет CI (job rust). Здесь они выключены сознательно: selftest
    # грузит seccomp-фильтр в собственный процесс, а что разрешает песочница
    # сборки nix — зависит от демона; ломать этим пересборку системы нельзя.
    doCheck = false;
    meta.mainProgram = "vpn-zone-seccomp";
  };

  # --- ЧАСТЬ 0в: ПЕСОЧНИЦА ФАЙЛОВОЙ СИСТЕМЫ ---
  # Третий слой поверх сети (зона) и данных (контейнер). Здесь программа теряет
  # доступ к $HOME целиком: вместо него tmpfs, наружу торчит только то, что ты
  # разрешил. Всё остальное она должна просить через ПОРТАЛЫ — а они в системе
  # уже стоят и работают (kde/gnome/gtk + xdg-document-portal).
  #
  # КЛЮЧЕВАЯ ХИТРОСТЬ — /.flatpak-info. Приложение идёт через порталы, только
  # если считает себя изолированным, а проверяет оно это по наличию этого файла
  # (так делают GTK, Qt, Chromium, Electron). Подкладываем его — и файловый
  # диалог начинает рисовать чужой процесс, отдавая программе ровно один
  # выбранный файл (через document-portal), камера и запись экрана начинают
  # спрашивать разрешение. То есть «андроидные» запросы получаются даром, писать
  # их не нужно.
  #
  # ЧЕГО ЗДЕСЬ НЕТ. Это не полная замена flatpak: у того ещё свой рантайм и
  # каталог правил на каждое приложение. Здесь программа берётся из nixpkgs и
  # видит /nix/store (иначе она попросту не запустится), так что «подменить
  # библиотеку» песочница не мешает — она мешает читать ТВОИ файлы.
  vpn-fs-sandbox = pkgs.writeShellScriptBin "vpn-fs-sandbox" ''
    set -eu
    appid=''${1:?нужен app-id}; shift
    # --name <песочница> — постоянная песочница с общим домом: в неё можно
    # запускать несколько программ, и они видят файлы друг друга, но не твои.
    # Без него дом создаётся временный (tmpfs) и исчезает вместе с программой.
    sbname=""
    if [ "''${1:-}" = "--name" ]; then shift; sbname=''${1:-}; shift || true; fi
    [ "''${1:-}" = "--" ] && shift || true
    [ $# -gt 0 ] || { echo "нечего запускать" >&2; exit 1; }

    home="${config.home.homeDirectory}"
    cfg="$home/.config/vpn-zones"
    permdir="$cfg/fs-perms"
    ${pkgs.coreutils}/bin/mkdir -p "$permdir"
    runtime="''${XDG_RUNTIME_DIR:-/run/user/$(${pkgs.coreutils}/bin/id -u)}"

    # --- РАЗРЕШЕНИЯ ---
    # Спрашиваем один раз на программу и запоминаем. Пусто = не давать ничего,
    # кроме портального обмена файлами.
    # У именованной песочницы разрешения общие: их выдают ей, а не каждой
    # программе по отдельности — иначе вторая программа спрашивала бы заново про
    # тот же самый дом.
    sbdir=""
    if [ -n "$sbname" ]; then
      sbdir="$home/.local/state/vpn-sandboxes/$sbname"
      ${pkgs.coreutils}/bin/mkdir -p "$sbdir/home"
      permfile="$sbdir/perms"
    else
      permfile="$permdir/$appid"
    fi
    # Без графики диалог показать негде, а ждать ответа некому — программа
    # просто зависла бы (проверено). Считаем, что не разрешено ничего.
    if [ ! -f "$permfile" ] && [ -z "''${WAYLAND_DISPLAY:-}''${DISPLAY:-}" ]; then
      : > "$permfile"
    fi
    if [ ! -f "$permfile" ]; then
      sel=$(${kdialog} --title "Доступ к файлам: $appid" \
        --separate-output \
        --checklist "Что показать программе? Ничего не отмечай — и она не увидит НИЧЕГО из твоих файлов: нужное сможет получить только через диалог выбора файла, по одному." \
        downloads "Загрузки (~/Downloads)" off \
        documents "Документы (~/Documents)" off \
        pictures "Изображения (~/Pictures)" off \
        x11 "Свой X-сервер (нужен Wine и старым программам)" off \
        home "ВЕСЬ домашний каталог — файловой изоляции не будет" off \
        2>/dev/null) || sel=""
      printf '%s\n' "$sel" > "$permfile"
    fi
    perms=$(${pkgs.coreutils}/bin/cat "$permfile" 2>/dev/null || true)

    binds=()
    case "$perms" in
      *home*)
        binds+=( --bind "$home" "$home" ) ;;
      *)
        if [ -n "$sbdir" ]; then
          # Постоянный дом песочницы: переживёт закрытие программы и виден всем,
          # кого запустили в эту же песочницу.
          binds+=( --bind "$sbdir/home" "$home" )
        else
          # tmpfs вместо дома: программа получает пустой $HOME и не видит ни
          # ключей, ни документов, ни конфигов остальных программ.
          binds+=( --tmpfs "$home" )
        fi
        case "$perms" in *downloads*) binds+=( --bind "$home/Downloads" "$home/Downloads" ) ;; esac
        case "$perms" in *documents*) binds+=( --bind "$home/Documents" "$home/Documents" ) ;; esac
        case "$perms" in *pictures*)  binds+=( --bind "$home/Pictures" "$home/Pictures" ) ;; esac
        ;;
    esac

    # --- АССОЦИАЦИИ ФАЙЛОВ И ССЫЛОК ---
    # В песочнице ~/.config пуст, поэтому mimeapps.list не виден, и xdg-open
    # подбирает обработчик сам: у Discord ссылка на вход открывалась в Chrome,
    # хотя браузер по умолчанию — zen. Пробрасываем только этот файл, только на
    # чтение: он крошечный и никаких секретов не содержит, зато ссылки уходят
    # туда, куда ты назначил.
    mimebind=()
    [ -f "$home/.config/mimeapps.list" ] && \
      mimebind=( --ro-bind "$home/.config/mimeapps.list" "$home/.config/mimeapps.list" )

    # --- /.flatpak-info ---
    # Минимальной секции [Application] хватает, чтобы тулкиты переключились на
    # порталы. Файл кладём во временный каталог и монтируем только на чтение.
    info=$(${pkgs.coreutils}/bin/mktemp -d)
    trap '${pkgs.coreutils}/bin/rm -rf "$info"' EXIT
    {
      echo "[Application]"
      echo "name=$appid"
      echo
      echo "[Instance]"
      echo "instance-id=$$"
      echo "session-bus-proxy=true"
      echo "system-bus-proxy=false"
    } > "$info/flatpak-info"

    # --- ШИНА ЧЕРЕЗ ФИЛЬТР ---
    # Без фильтра программа через сессионную шину дотянется до Secret Service
    # (то есть до KWallet со всеми паролями), до списка окон и до чужих
    # приложений. Пропускаем только порталы и уведомления.
    proxy="$info/bus"
    ${pkgs.xdg-dbus-proxy}/bin/xdg-dbus-proxy "''${DBUS_SESSION_BUS_ADDRESS:-unix:path=$runtime/bus}" "$proxy" \
      --filter \
      --talk=org.freedesktop.portal.* \
      --talk=org.freedesktop.Notifications \
      --talk=org.kde.StatusNotifierWatcher \
      >/dev/null 2>&1 &
    proxypid=$!
    trap '${pkgs.coreutils}/bin/kill $proxypid 2>/dev/null || true; ${pkgs.coreutils}/bin/rm -rf "$info"' EXIT
    for _ in $(seq 1 50); do [ -S "$proxy" ] && break; ${pkgs.coreutils}/bin/sleep 0.1; done

    # Сокеты, которые пробрасываем поимённо: композитор (уже ограниченный
    # wl-sandbox, если он был), звук и наш прокси шины. Всё остальное из
    # $XDG_RUNTIME_DIR программе не видно.
    sockets=( --tmpfs "$runtime" )
    [ -n "''${WAYLAND_DISPLAY:-}" ] && [ -S "$runtime/$WAYLAND_DISPLAY" ] && \
      sockets+=( --ro-bind "$runtime/$WAYLAND_DISPLAY" "$runtime/$WAYLAND_DISPLAY" )
    [ -S "$runtime/pipewire-0" ] && sockets+=( --ro-bind "$runtime/pipewire-0" "$runtime/pipewire-0" )
    [ -S "$runtime/pulse/native" ] && sockets+=( --ro-bind "$runtime/pulse/native" "$runtime/pulse/native" )
    sockets+=( --bind "$proxy" "$runtime/bus" )
    # X-сокет ХОСТА не пробрасываем никогда: в общем X-сервере все клиенты видят
    # окна и ввод друг друга — это дыра ровно того размера, который мы
    # закрывали. Так же считает и сам flatpak: его --socket=x11 документирован
    # как небезопасный, а рекомендуется fallback-x11, то есть «X только если нет
    # Wayland».
    #
    # Вместо этого при разрешении x11 внутри песочницы поднимается СВОЙ
    # xwayland-satellite: приложение получает отдельный X-сервер, в котором,
    # кроме него, никого нет. Он подключается к нашему уже ограниченному
    # wayland-сокету, так что через X обойти security-context тоже не выйдет.
    #
    # Electron сюда не относится: ему хватает подсказки уйти на Wayland (см.
    # ELECTRON_OZONE_PLATFORM_HINT ниже) — проверено на Discord, который без неё
    # падал с «Missing X server or $DISPLAY».
    # Подстановки вида ''${var:+…} с кавычками внутри НЕ годятся: кавычки в них
    # остаются литеральными символами, аргументы разъезжаются, и bwrap пытается
    # выполнить сам номер дисплея («execvp :149»). Поэтому массивы.
    # Узлы GPU. Одного /dev/dri мало: на NVIDIA драйверу нужны ещё /dev/nvidia*,
    # без них EGL внутри падает («failed to create dri2 screen»), а Electron
    # намертво виснет на заставке — проверено на Discord.
    devbinds=()
    for d in /dev/dri /dev/nvidia*; do
      [ -e "$d" ] && devbinds+=( --dev-bind-try "$d" "$d" )
    done

    xdisp=""
    xenv=( --unsetenv DISPLAY )
    xlauncher=()
    case "$perms" in
      *x11*)
        xdisp=":''$(( (RANDOM % 400) + 100 ))"
        xenv=( --setenv DISPLAY "$xdisp" )
        xlauncher=( ${pkgs.bash}/bin/bash -c '
          xwayland-satellite "$1" >/dev/null 2>&1 &
          shift
          # Секунда на подъём сервера: без неё программа стартует раньше, чем
          # появится сокет, и падает с «cannot open display».
          ${pkgs.coreutils}/bin/sleep 1
          exec "$@"' -- "$xdisp" )
        ;;
    esac

    # --- SECCOMP: ФИЛЬТР СИСТЕМНЫХ ВЫЗОВОВ ---
    # Слой, которого в bash не могло быть в принципе: программу для ядра
    # генерирует только код (крейт rust/, libseccomp). Набор — по образцу
    # flatpak, и он не про «запретить всё», а про несколько вызовов, которыми
    # из песочницы дотягиваются наружу или до ядра:
    #   • ioctl(TIOCSTI/TIOCLINUX) — вставка символов во ввод ТВОЕГО терминала:
    #     программа, запущенная из шелла, могла бы «напечатать» туда команду, и
    #     выполнилась бы она уже вне песочницы;
    #   • ptrace — присоединение к чужим процессам того же uid (а uid у
    #     песочницы общий со всей сессией);
    #   • keyctl/add_key/request_key, syslog, perf_event_open, acct, quotactl,
    #     uselib, NUMA-вызовы — поверхность атаки на ядро, десктопной программе
    #     не нужная;
    #   • personality — только PER_LINUX (остальные ослабляют защиту userspace);
    #   • новый mount-API и clone3 отвечают ENOSYS, а не EPERM, чтобы libc и
    #     программы уходили на старый путь, а не падали.
    # Вложенные user namespace НЕ запрещены, и это осознанно. У flatpak такой
    # запрет есть, но там же есть zypak; в NixOS нет ни его, ни setuid
    # chrome-sandbox, поэтому Chromium и все Electron-программы строят СВОЙ
    # вложенный userns — запретишь, и они не стартуют вовсе («No usable
    # sandbox!»). Наружу он всё равно не выводит: права даёт только над своими
    # новыми пустыми namespace. Кому нужно строже — `vpn-zone-seccomp export
    # --deny-userns`.
    #
    # Мягкая деградация, как и в остальных слоях: не собрался фильтр —
    # предупреждаем и запускаем без него.
    # stderr генератора НЕ глушим: он пишет туда только про пропущенные правила
    # (libseccomp не знает такого вызова) и про ошибки — молчать о дырявом
    # фильтре нельзя.
    seccompargs=()
    if ${vpn-zone-rust}/bin/vpn-zone-seccomp export > "$info/seccomp.bpf" \
       && [ -s "$info/seccomp.bpf" ]; then
      # bwrap читает программу из ДЕСКРИПТОРА (--seccomp FD), а редирект нельзя
      # положить в массив аргументов — открываем его заранее через exec. Номер
      # произвольный, лишь бы свободный; bwrap прочитает и закроет его сам.
      exec 34< "$info/seccomp.bpf"
      seccompargs=( --seccomp 34 )
    else
      echo "vpn-fs-sandbox: seccomp-фильтр не собрался — запускаю без него" >&2
    fi

    # НЕ exec: прокси шины надо погасить после выхода программы, а после exec
    # обработчик выхода уже не сработает — и прокси остался бы висеть. Заодно
    # его вывод уводится в /dev/null: иначе он держит открытым stdout, и вызов
    # выглядит зависшим, хотя программа давно закончила.
    ${pkgs.bubblewrap}/bin/bwrap \
      --ro-bind /nix/store /nix/store \
      --ro-bind /run/current-system /run/current-system \
      --ro-bind-try /run/opengl-driver /run/opengl-driver \
      --ro-bind-try /run/opengl-driver-32 /run/opengl-driver-32 \
      --ro-bind /etc /etc \
      --ro-bind-try /sys /sys \
      `# /etc/resolv.conf — симлинк в /run/systemd/resolve, поэтому без этой` \
      `# строки внутри песочницы не резолвятся имена: сам /run не пробрасывается` \
      --ro-bind-try /run/systemd/resolve /run/systemd/resolve \
      --dev /dev \
      "''${devbinds[@]}" \
      --proc /proc \
      --tmpfs /tmp \
      "''${binds[@]}" \
      "''${mimebind[@]}" \
      "''${sockets[@]}" \
      --ro-bind "$info/flatpak-info" /.flatpak-info \
      --setenv HOME "$home" \
      --setenv XDG_RUNTIME_DIR "$runtime" \
      --setenv DBUS_SESSION_BUS_ADDRESS "unix:path=$runtime/bus" \
      --setenv FLATPAK_ID "$appid" \
      --setenv ELECTRON_OZONE_PLATFORM_HINT auto \
      --setenv NIXOS_OZONE_WL 1 \
      --unsetenv DBUS_SYSTEM_BUS_ADDRESS \
      `# Без разрешения x11 DISPLAY сбрасывается: иначе тулкиты видят` \
      `# унаследованный :0, идут на X и падают вместо перехода на Wayland` \
      "''${xenv[@]}" \
      "''${seccompargs[@]}" \
      --unshare-pid --unshare-ipc --unshare-uts --unshare-cgroup-try \
      --die-with-parent \
      -- "''${xlauncher[@]}" "$@"
    rc=$?
    ${pkgs.coreutils}/bin/kill $proxypid 2>/dev/null || true
    exit $rc
  '';

  # --- ЧАСТЬ 1: то, что исполняется ВНУТРИ зоны ---
  # Настраивает туннель. Запускается уже в новом net+mount namespace под uid 0.
  zoneInit = pkgs.writeShellScript "vpn-zone-init" ''
    set -eu
    name="$1"
    dir="${stateDir}/$name"
    conf="$dir/config.conf"

    echo $$ > "$dir/zone.pid"

    # --- ЗОНА БЕЗ СЕТИ ---
    # Особый случай: ни туннеля, ни выхода наружу — только loopback. Именно она
    # делает возможной политику «по умолчанию интернета нет»: программа
    # запускается и работает, но в сеть не ходит вообще, причём не потому, что
    # ей запретили правилом, а потому, что маршрута физически не существует.
    if [ -f "$dir/offline" ]; then
      ${iproute} link set lo up
      touch "$dir/ready"
      echo "зона $name: без сети (только loopback)"
      exec ${pkgs.coreutils}/bin/sleep infinity
    fi

    # Ждём, пока pasta настроит выходной интерфейс: до этого маршрута наружу нет
    # и добавлять маршрут до endpoint'а некуда.
    for _ in $(seq 1 50); do
      ${iproute} -4 route show default | grep -q . && break
      sleep 0.1
    done

    # Разбираем по ключевым словам, а не по номерам полей: у pasta маршрут имеет
    # вид «default dev hostif scope link» (без via), у обычной сети —
    # «default via 192.168.1.1 dev enp4s0 …». Позиционный разбор ловил во втором
    # случае слово «link» вместо имени интерфейса — проверено, маршрут до
    # VPN-сервера тогда не добавлялся вовсе.
    defroute=$(${iproute} -o -4 route show default | head -1)
    outif=$(echo "$defroute" | ${pkgs.gawk}/bin/awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    outgw=$(echo "$defroute" | ${pkgs.gawk}/bin/awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}')
    if [ -z "''${outif:-}" ]; then
      echo "зона $name: pasta не дала маршрут наружу" >&2
      exit 1
    fi

    # awg setconf понимает только ключи протокола. Address/DNS/MTU — это указания
    # для wg-quick, и их надо применить руками (см. ниже), а из файла убрать,
    # иначе setconf упадёт на первой же такой строке.
    # \r чистим и здесь, а не только при `vpn-zone add`: конфиг могли положить в
    # каталог зоны руками, а диагностика этой ошибки крайне неприятна — в
    # сообщении ip возврат каретки не виден (см. подробности в vpn-zone add).
    #
    # Второй фильтр — строки с ПУСТЫМ значением. Свежая Amnezia кладёт в конфиг
    # параметры пакетов-приманок I1…I5 и заполняет не все: получается «I2 = ».
    # awg setconf на такой строке падает целиком — «Line unrecognized: `I2='»,
    # и зона не поднимается вовсе. Проверено на двух твоих конфигах: со старым
    # набором (Jc/S/H) они работали, с новым (плюс I1…I5) — падали.
    # Выбрасываем только пустые: заполненные параметры обфускации нужны, без них
    # сервер не ответит.
    stripped="$dir/.stripped.conf"
    ${pkgs.gnused}/bin/sed 's/\r$//' "$conf" \
      | ${pkgs.gnugrep}/bin/grep -vE '^[[:space:]]*(Address|DNS|MTU|Table|PreUp|PostUp|PreDown|PostDown|SaveConfig)' \
      | ${pkgs.gnugrep}/bin/grep -vE '^[[:space:]]*[A-Za-z0-9]+[[:space:]]*=[[:space:]]*$' \
      > "$stripped"

    field() {
      ${pkgs.gnugrep}/bin/grep -iE "^[[:space:]]*$1[[:space:]]*=" "$conf" \
        | ${pkgs.gnused}/bin/sed 's/.*=//' | tr -d " \r\t" | head -1
    }
    # Address бывает списком через запятую и смешивает семейства
    # («10.8.1.10/32, fd00::2/128») — берём ВСЕ, а не только первый: раньше
    # v6-адрес молча выбрасывался, а конфиг только с v6 валил зону на
    # `ip -4 addr add`.
    addresses=$(field Address | tr ',' ' ')
    mtu=$(field MTU)
    endpoint=$(field Endpoint)
    dnslist=$(field DNS)

    # --- МАРШРУТ ДО САМОГО VPN-СЕРВЕРА ---
    # Он обязан идти МИМО туннеля, иначе получится петля: пакеты туннеля
    # заворачивались бы в туннель. Резолвим имя, пока DNS ещё хостовый.
    #
    # Endpoint бывает трёх видов: host:port, v4:port и [v6]:port. Прежний
    # разбор ''${endpoint%:*} резал v6-литерал по последнему двоеточию и
    # получал мусор, а имя хоста резолвил только в v4. Заодно: «содержит
    # букву — значит имя» ловило и hex-цифры v6 — сначала различаем по
    # двоеточию, буквы проверяем только после.
    epaddr=''${endpoint%:*}
    ep6=0
    case "$epaddr" in
      \[*\]) epaddr=''${epaddr#\[}; epaddr=''${epaddr%\]}; ep6=1 ;;
      *:*) ep6=1 ;;
      *[a-zA-Z]*)
        r=$(${pkgs.getent}/bin/getent ahostsv4 "$epaddr" \
          | ${pkgs.gawk}/bin/awk 'NR==1{print $1}')
        if [ -z "''${r:-}" ]; then
          r=$(${pkgs.getent}/bin/getent ahostsv6 "$epaddr" \
            | ${pkgs.gawk}/bin/awk 'NR==1{print $1}')
          [ -n "''${r:-}" ] && ep6=1
        fi
        epaddr=''${r:-} ;;
    esac
    # Ошибку здесь НЕ глушим: без этого маршрута пакеты самого туннеля пойдут
    # в туннель, и зона просто не заработает — молчать об этом нельзя.
    if [ -z "''${epaddr:-}" ]; then
      echo "зона $name: в конфиге нет Endpoint — маршрут до сервера не задан" >&2
    elif [ "$ep6" = 1 ]; then
      # v6-endpoint: маршрут по v6-умолчанию от pasta (есть, только если v6
      # есть у самого хоста).
      d6=$(${iproute} -o -6 route show default 2>/dev/null | head -1)
      out6if=$(echo "$d6" | ${pkgs.gawk}/bin/awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
      out6gw=$(echo "$d6" | ${pkgs.gawk}/bin/awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}')
      if [ -z "''${out6if:-}" ]; then
        echo "зона $name: endpoint IPv6, а v6-маршрута наружу нет — туннель не заработает" >&2
      else
        if [ -n "''${out6gw:-}" ]; then
          ${iproute} -6 route add "$epaddr/128" via "$out6gw" dev "$out6if"
        else
          ${iproute} -6 route add "$epaddr/128" dev "$out6if"
        fi || echo "зона $name: не удалось добавить v6-маршрут до $epaddr" >&2
      fi
    else
      if [ -n "''${outgw:-}" ]; then
        ${iproute} route add "$epaddr/32" via "$outgw" dev "$outif"
      else
        ${iproute} route add "$epaddr/32" dev "$outif" scope link
      fi || echo "зона $name: не удалось добавить маршрут до $epaddr через $outif" >&2
    fi

    # --- ТУННЕЛЬ ---
    # Обычный путь — ядерный amneziawg (он понимает и чистые WG-конфиги).
    # Модуля нет (система без Amnezia, CI): конфиг без параметров обфускации
    # поднимаем ядерным wireguard и утилитой wg; с обфускацией — честно
    # падаем, без модуля такой туннель не собрать.
    wgtool=${awg}
    if ! ${iproute} link add awg0 type amneziawg 2>/dev/null; then
      if ${pkgs.gnugrep}/bin/grep -qiE '^[[:space:]]*(Jc|Jmin|Jmax|S1|S2|H[1-4]|I[1-5])[[:space:]]*=' "$stripped"; then
        echo "зона $name: модуль amneziawg недоступен, а конфиг с обфускацией — не поднять" >&2
        exit 1
      fi
      ${iproute} link add awg0 type wireguard
      wgtool=${wg}
      echo "зона $name: модуля amneziawg нет — использую ядерный wireguard"
    fi
    "$wgtool" setconf awg0 "$stripped"
    has6=0
    for a in ''${addresses:-}; do
      case "$a" in
        *:*) if ${iproute} -6 addr add "$a" dev awg0 2>/dev/null; then has6=1
             else echo "зона $name: v6-адрес $a не назначился — IPv6 в зоне будет закрыт" >&2; fi ;;
        *) ${iproute} -4 addr add "$a" dev awg0 ;;
      esac
    done
    ${iproute} link set awg0 mtu "''${mtu:-1420}" up
    ${iproute} route replace default dev awg0
    # --- IPv6: ЛИБО В ТУННЕЛЬ, ЛИБО ВЫКЛЮЧЕН ---
    # Принцип: у пакета ЛЮБОГО семейства не должно быть пути мимо туннеля
    # (docs/LEAK-MODEL.md). pasta даёт зоне и v6-связность с хостом, а в
    # туннель до сих пор заворачивался только v4 default — весь IPv6-трафик
    # приложений шёл В ОБХОД VPN. Теперь: есть v6-адрес туннеля — v6 default
    # тоже в туннель; нет — IPv6 в зоне выключается целиком (sysctl своей
    # netns, хоста не касается), а если выключить не вышло — запрещающий
    # маршрут. Fail-closed. Вернуть v6 приложения не могут: они входят в зону
    # без capabilities.
    if [ ! -e /proc/net/if_inet6 ]; then
      : # ядро вообще без IPv6 — закрывать нечего
    elif [ "$has6" = 1 ]; then
      ${iproute} -6 route replace default dev awg0
    elif [ "$ep6" = 1 ]; then
      # Транспорт туннеля сам ходит по v6 — выключать семейство нельзя.
      # Закрываем только default: точный /128 до сервера остаётся (он
      # специфичнее), а всему остальному v6-трафику идти некуда.
      ${iproute} -6 route replace default unreachable \
        || echo "зона $name: не удалось закрыть v6 default — возможна утечка v6" >&2
    elif ! echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null; then
      ${iproute} -6 route replace default unreachable 2>/dev/null \
        || echo "зона $name: не удалось закрыть IPv6 — возможна утечка v6 мимо туннеля" >&2
    fi

    # --- ЗАКРЫВАЕМ КЭШИРУЮЩИЙ РЕЗОЛВЕР ХОСТА ---
    # Это НЕ теория: в NixOS работает nsncd (сокет /run/nscd/socket), и glibc
    # ходит за именами к нему, а не к DNS из resolv.conf. Демон живёт в сети
    # ХОСТА, поэтому имена внутри зоны резолвились мимо туннеля — проверено на
    # живой зоне: `getent` отвечал при RX=0 на awg0, то есть запрос уходил
    # наружу помимо VPN. Классическая утечка DNS, и подмена resolv.conf её не
    # лечит.
    #
    # tmpfs поверх каталога прячет сокет только внутри зоны: glibc его не
    # находит и идёт напрямую к серверам из resolv.conf, то есть через туннель.
    # У остальной системы nsncd продолжает работать как раньше.
    for nscd in /run/nscd /var/run/nscd; do
      if [ -d "$nscd" ]; then
        ${pkgs.util-linux}/bin/mount -t tmpfs -o mode=0755,size=64k tmpfs "$nscd" \
          || echo "зона $name: не удалось спрятать $nscd — возможна утечка DNS" >&2
        break
      fi
    done

    # --- DNS ЗОНЫ ---
    # Без этого запросы уходили бы к резолверу хоста в обход туннеля — самая
    # частая утечка. mount --bind виден только внутри зоны: у остальной системы
    # /etc/resolv.conf остаётся прежним.
    if [ -n "''${dnslist:-}" ]; then
      : > "$dir/resolv.conf"
      echo "$dnslist" | tr ',' '\n' | while read -r ns; do
        [ -n "$ns" ] && echo "nameserver $ns" >> "$dir/resolv.conf"
      done
    else
      # Конфиг без DNS= — раньше зона молча оставалась с resolv.conf хоста, а
      # там локальный резолвер (192.168.1.1 или стаб 127.0.0.53), который
      # изнутри зоны недостижим: имена просто переставали резолвиться, и
      # выглядело это как «интернет есть, но ничего не открывается».
      # Публичные резолверы через туннель — рабочий и не утекающий дефолт.
      { echo "nameserver 1.1.1.1"; echo "nameserver 9.9.9.9"; } > "$dir/resolv.conf"
      echo "зона $name: в конфиге нет DNS= — беру 1.1.1.1 и 9.9.9.9 (через туннель)"
    fi
    ${pkgs.util-linux}/bin/mount --bind "$dir/resolv.conf" /etc/resolv.conf

    # ПРОФИЛЬ ЗДЕСЬ НЕ МОНТИРУЕТСЯ, И ЭТО ВАЖНО. Первым заходом слой данных
    # накладывался прямо тут, на всю зону — и профиль оказывался намертво
    # привязан к VPN: настроил браузер в зоне «nl», заблокировали сервер — и
    # настроенное окружение уезжает вместе с ним. Теперь профиль — отдельная
    # сущность, монтируется при запуске программы (см. крейт rust/, модуль
    # profile — `vpn-zone-core profile-run`), поэтому один и тот же профиль
    # можно поднять хоть в другой зоне, хоть без VPN вовсе.
    touch "$dir/ready"
    echo "зона $name поднята: $(${iproute} -br -4 addr show awg0)"

    # --- ЗЕРКАЛО СОСТОЯНИЯ ТУННЕЛЯ ---
    # `awg show` требует прав на netlink, а программы (и `vpn-zone status`)
    # заходят в зону под обычным uid и видят пустоту — состояние туннеля было
    # недоступно вообще. Поэтому пишем его отсюда, изнутри, где права есть.
    # Пять секунд — компромисс: рукопожатие видно почти сразу, а нагрузки нет.
    (
      while :; do
        "$wgtool" show awg0 > "$dir/status.tmp" 2>/dev/null \
          && ${pkgs.coreutils}/bin/mv "$dir/status.tmp" "$dir/status"
        ${pkgs.coreutils}/bin/sleep 5
      done
    ) &

    # Первое рукопожатие — главный признак «конфиг живой». Печатаем в журнал:
    # по нему сразу видно, стоит ли возиться с этой зоной дальше.
    ${pkgs.coreutils}/bin/sleep 4
    if "$wgtool" show awg0 latest-handshakes 2>/dev/null | ${pkgs.gawk}/bin/awk '{exit ($2>0)?0:1}'; then
      echo "зона $name: рукопожатие прошло — туннель живой"
    else
      echo "зона $name: рукопожатия нет. Либо конфиг нерабочий, либо сервер недоступен" >&2
    fi

    # Держим namespace живым. Умрёт этот процесс — исчезнет зона, а вместе с ней
    # и сеть у всего, что в ней работало (это и есть kill switch).
    exec ${pkgs.coreutils}/bin/sleep infinity
  '';

  # --- ЧАСТЬ 2: то, что создаёт зону снаружи ---
  # Запускается юнитом vpn-zone@<имя>.service.
  zoneHolder = pkgs.writeShellScript "vpn-zone-holder" ''
    set -eu
    name="$1"
    dir="${stateDir}/$name"
    if [ ! -f "$dir/config.conf" ] && [ ! -f "$dir/offline" ]; then
      echo "нет ни конфига $dir/config.conf, ни отметки offline" >&2
      exit 1
    fi
    rm -f "$dir/zone.pid" "$dir/ready"

    uid=$(${pkgs.coreutils}/bin/id -u)
    gid=$(${pkgs.coreutils}/bin/id -g)
    # Первый диапазон из /etc/subuid — из него берётся uid 0 внутри зоны.
    subuid=$(${pkgs.gawk}/bin/awk -F: -v u="$(${pkgs.coreutils}/bin/id -un)" \
      '$1==u {print $2; exit}' /etc/subuid)
    subgid=$(${pkgs.gawk}/bin/awk -F: -v u="$(${pkgs.coreutils}/bin/id -un)" \
      '$1==u {print $2; exit}' /etc/subgid)
    if [ -z "''${subuid:-}" ] || [ -z "''${subgid:-}" ]; then
      echo "в /etc/subuid нет диапазона для тебя — без него rootless-зона невозможна" >&2
      exit 1
    fi

    # ДВОЙНОЙ МАППИНГ, объяснение — в шапке файла.
    exec ${pkgs.util-linux}/bin/unshare \
      --user \
      --map-users=0:"$subuid":1 --map-users="$uid":"$uid":1 \
      --map-groups=0:"$subgid":1 --map-groups="$gid":"$gid":1 \
      --setuid 0 --setgid 0 \
      -- ${pkgs.bash}/bin/bash -c '
        set -eu
        name="$1"; dir="$2"
        # Зона (net+mount namespace) — отдельным процессом, чтобы pasta,
        # оставшаяся в сети хоста, могла к ней подключиться снаружи.
        ${pkgs.util-linux}/bin/unshare --net --mount --propagation private --fork \
          ${zoneInit} "$name" &
        zonewatch=$!

        for _ in $(seq 1 50); do [ -f "$dir/zone.pid" ] && break; sleep 0.1; done
        zonepid=$(cat "$dir/zone.pid" 2>/dev/null || true)
        [ -n "''${zonepid:-}" ] || { echo "зона не запустилась" >&2; exit 1; }

        # Зоне без сети pasta не нужна — в этом весь её смысл.
        pastapid=""
        if [ ! -f "$dir/offline" ]; then
          # -I hostif: имя выходного интерфейса задаём явно. По умолчанию pasta
          # копирует имя интерфейса хоста, и если он вдруг называется awg0
          # (когда сам хост под VPN), внутри зоны случилось бы столкновение имён.
          ${pasta} --netns /proc/"$zonepid"/ns/net --config-net -q -I hostif -f &
          pastapid=$!
        fi

        trap "kill $pastapid $zonewatch 2>/dev/null || true" TERM INT
        wait $zonewatch
      ' -- "$name" "$dir"
  '';

  # --- ЧАСТЬ 3: пользовательский CLI ---
  vpn-zone = pkgs.writeShellScriptBin "vpn-zone" ''
    set -eu
    export PATH="${
      lib.makeBinPath [
        pkgs.coreutils
        pkgs.util-linux
        pkgs.gnugrep
        pkgs.gnused
        pkgs.gawk
        pkgs.systemd
      ]
    }:${config.home.profileDirectory}/bin:$PATH"
    root="${stateDir}"
    # Профили живут ОТДЕЛЬНО от зон — в этом вся суть разделения: сеть можно
    # сменить или удалить, а настроенное окружение остаётся.
    profiles="${profilesDir}"
    mkdir -p "$root" "$profiles"

    usage() {
      cat <<'EOF'
    vpn-zone — сетевые зоны с VPN, без root

      vpn-zone add <имя> <файл.conf>   создать зону из конфига AmneziaWG/WireGuard
      vpn-zone up <имя>                поднять
      vpn-zone down <имя>              опустить
      vpn-zone list                    список зон и их состояние
      vpn-zone status <имя>            подробности (адрес, handshake)
      vpn-zone run <имя> -- <кмд>      запустить программу внутри зоны
      vpn-zone rm <имя>                удалить зону вместе с ярлыками
      vpn-zone sync                    пересобрать .desktop-ярлыки
      vpn-zone mode <режим>            как ярлыки работают:
                                         picker   — один ярлык, спрашивает сеть
                                                    при запуске (по умолчанию)
                                         per-zone — отдельный ярлык на каждую зону
                                         both     — и то, и другое
                                         off      — не трогать ярлыки вовсе
      vpn-zone default <вариант>       что предлагать в пикере для незнакомой
                                       программы: offline (по умолчанию), direct
                                       или имя зоны
      vpn-zone gc                      убрать зависшие держатели зон, осиротевшую
                                       обвязку и мёртвые записи
      vpn-zone perms list|reset <прог.|--all>
                                       какие доступы к файлам выданы программам
                                       в песочнице; reset — спросить заново
      vpn-zone sandbox create|list|rm <имя>
                                       именованные песочницы: свой дом, общий для
                                       всех программ, запущенных в этой песочнице
      vpn-zone run <имя> --sandbox <п> -- <кмд>
                                       запустить в именованной песочнице
      vpn-zone run <имя> --fs-sandbox -- <кмд>
                                       запустить в песочнице файловой системы:
                                       вместо $HOME — пустой каталог, наружу
                                       видно только разрешённое, остальное — через
                                       диалог выбора файла (порталы)
      vpn-zone run <имя> --tmp-profile -- <кмд>
                                       запустить в одноразовом контейнере: слой
                                       создаётся в /tmp и стирается по выходе
      vpn-zone default-profile <v>     контейнер по умолчанию для всех запусков:
                                       ask (спрашивать), main (основной),
                                       own (своя песочница у каждой программы)
                                       или имя контейнера
      vpn-zone pins                    какие программы закреплены за сетями
      vpn-zone forget <прог.|--all>    снять закрепление (снова будет спрашивать)
      vpn-zone isolate <overlay|off>   свой слой профиля у зоны (overlay — по
                                       умолчанию). Без него браузер откроет окно
                                       в уже запущенном процессе, мимо VPN
      vpn-zone reset-profile <имя>     очистить слой профиля зоны
      vpn-zone wayland-sandbox on|off  отбирать ли у программ захват экрана,
                                       чтение буфера в фоне и эмуляцию ввода
                                       (по умолчанию on; исключения —
                                       ~/.config/vpn-zones/wayland-allow)
      vpn-zone check <имя>             прошло ли рукопожатие (жив ли конфиг)
      vpn-zone lock|unlock <имя>       запретить/разрешить программам этой зоны
                                       запускать что-либо в ДРУГИХ сетях
                                       (по умолчанию разрешено)
    EOF
    }

    zone_pid() {
      p=$(cat "$root/$1/zone.pid" 2>/dev/null || true)
      [ -n "''${p:-}" ] && [ -d "/proc/$p" ] && echo "$p"
    }

    cmd=''${1:-}; [ $# -gt 0 ] && shift || true
    case "$cmd" in
      add)
        name=''${1:?нужно имя зоны}; conf=''${2:?нужен путь к .conf}
        case "$name" in *[!a-zA-Z0-9_-]*) echo "имя только из букв, цифр, - и _" >&2; exit 1;; esac
        [ -f "$conf" ] || { echo "нет файла $conf" >&2; exit 1; }
        grep -qiE '^[[:space:]]*\[Interface\]' "$conf" || {
          echo "$conf не похож на конфиг WireGuard/AmneziaWG" >&2; exit 1; }
        mkdir -p "$root/$name"
        # Копия, а не ссылка: конфиг с приватным ключом должен пережить и
        # перемещение исходного файла, и его удаление.
        #
        # И сразу нормализуем переводы строк. Amnezia отдаёт .conf в формате
        # Windows (CRLF) — проверено на настоящем файле: там 21 строка с \r.
        # Без этого «\r» попадает В КОНЕЦ ЗНАЧЕНИЯ, и зона падает на первой же
        # команде: `ip addr add 10.8.1.10/32<CR>` → «inet prefix is expected
        # rather than "10.8.1.10/32"». Ошибка выглядит бессмысленно, потому что
        # в сообщении возврат каретки не виден.
        install -m 600 /dev/null "$root/$name/config.conf"
        sed 's/\r$//' "$conf" > "$root/$name/config.conf"
        echo "зона $name создана"
        ;;
      up)   name=''${1:?нужно имя}; systemctl --user start "vpn-zone@$name.service"
            for _ in $(seq 1 100); do [ -f "$root/$name/ready" ] && break; sleep 0.1; done
            if [ -f "$root/$name/ready" ]; then echo "зона $name поднята"
            else echo "зона $name не поднялась — journalctl --user -u vpn-zone@$name" >&2; exit 1; fi
            ;;
      down) name=''${1:?нужно имя}; systemctl --user stop "vpn-zone@$name.service"; echo "зона $name опущена" ;;
      list)
        for d in "$root"/*/; do
          [ -d "$d" ] || continue
          n=$(basename "$d")
          if [ -n "$(zone_pid "$n")" ]; then echo "$n — поднята"; else echo "$n — опущена"; fi
        done
        ;;
      status)
        name=''${1:?нужно имя}; p=$(zone_pid "$name" || true)
        [ -n "''${p:-}" ] || { echo "зона $name не поднята"; exit 1; }
        nsenter --preserve-credentials -U -n -m -t "$p" -- ${iproute} -br -4 addr show
        # Состояние туннеля читаем из зеркала, которое пишет сама зона: изнутри
        # под обычным uid `awg show` прав не имеет и молчит.
        [ -f "$root/$name/status" ] && { echo; cat "$root/$name/status"; }
        ;;
      lock|unlock)
        zname=''${1:?нужно имя зоны}
        [ -d "$root/$zname" ] || { echo "зоны $zname нет" >&2; exit 1; }
        if [ "$cmd" = "lock" ]; then
          : > "$root/$zname/no-escape"
          echo "зона $zname заперта: программы из неё не смогут запускать что-либо в других сетях"
        else
          rm -f "$root/$zname/no-escape"
          echo "зона $zname открыта: запуск из неё в другой сети снова разрешён"
        fi
        ;;
      check)
        # «Этот конфиг вообще рабочий?» — короткий ответ по факту рукопожатия.
        name=''${1:?нужно имя}
        [ -n "$(zone_pid "$name" || true)" ] || { echo "зона $name не поднята"; exit 2; }
        # Отличаем «рукопожатия нет» от «данных нет»: зеркало состояния пишет
        # сама зона, и у зон, поднятых до его появления, файла просто не будет —
        # без этой проверки check уверенно объявлял бы живой туннель мёртвым.
        if [ ! -f "$root/$name/status" ]; then
          echo "зона $name: состояние неизвестно — она поднята старой версией,"
          echo "перезапусти её: vpn-zone down $name && vpn-zone up $name"
          exit 3
        fi
        hs=$(grep -A20 "peer" "$root/$name/status" 2>/dev/null \
          | grep -i "latest handshake" | head -1)
        if [ -n "''${hs:-}" ]; then
          echo "зона $name: туннель живой ($(echo "$hs" | sed 's/^ *//'))"
        else
          echo "зона $name: рукопожатия нет — конфиг мёртвый или сервер недоступен"
          exit 1
        fi
        ;;
      run)
        # --- ЗАПУСК ИЗ ЗОНЫ: ДЕЛЕГИРУЕМ НАРУЖУ ---
        # Симптом, из-за которого это появилось: в Telegram, запущенном в зоне,
        # клик по ссылке открывал диалог выбора сети, а браузер не появлялся
        # вовсе. Причина — ядро: процесс, уже находящийся в одном user+net
        # namespace, НЕ МОЖЕТ перейти в другой («nsenter: reassociate to
        # namespaces failed»). А «Прямой интернет» в этом случае молча
        # наследовал сеть зоны, то есть прямым не был.
        #
        # Выход — попросить systemd --user: он живёт в корневом namespace, его
        # сокет виден изнутри зоны, и запущенная им команда стартует снаружи.
        # Оттуда переход в любую зону уже разрешён. Графическое окружение у него
        # своё, полное (WAYLAND_DISPLAY, DBUS, XDG_RUNTIME_DIR) — проверено.
        # ЗАМОК. Для VPN-зон выход наружу — удобство: программа в зоне и так
        # видит весь $HOME, dbus и композитор, так что настоящей границы он не
        # ломает. Но зона может быть карантинной (недоверенная программа) — тогда
        # выпускать её запуски в другую сеть нельзя. `vpn-zone lock <зона>`
        # ставит запрет: чужой выбор сети игнорируется, и всё, что программа
        # запускает, остаётся в её же зоне.
        if [ -n "''${VPN_ZONE_CURRENT:-}" ] && [ -z "''${VPN_ZONE_DELEGATED:-}" ]; then
          if [ -f "$root/''${VPN_ZONE_CURRENT}/no-escape" ]; then
            echo "зона ''${VPN_ZONE_CURRENT} заперта: запускаем в ней же, а не в «''${1:-?}»" >&2
            # Никаких nsenter: мы УЖЕ внутри этой зоны, а войти в неё повторно
            # из вложенного namespace ядро не даёт («reassociate to namespaces
            # failed»). Просто отбрасываем аргументы выбора и запускаем.
            # Профиль тоже отбрасывается: смонтировать слой отсюда нечем — прав
            # на это внутри зоны уже нет.
            shift
            case "''${1:-}" in
              --profile|-p) shift 2 ;;
              --tmp-profile) shift; [ "''${1:-}" = "--join" ] && shift 2 ;;
            esac
            [ "''${1:-}" = "--" ] && shift
            [ $# -gt 0 ] || { echo "нечего запускать" >&2; exit 1; }
            exec "$@"
          else
            exec systemd-run --user --quiet --collect \
              --setenv=VPN_ZONE_DELEGATED=1 \
              -- ${config.home.profileDirectory}/bin/vpn-zone run "$@"
          fi
        fi
        name=''${1:?нужно имя}; shift
        profile=""; profiledir=""; ephemeral=0; fssandbox=0
        if [ "''${1:-}" = "--profile" ] || [ "''${1:-}" = "-p" ]; then
          shift; profile=''${1:?нужно имя профиля}; shift
          profiledir="$profiles/$profile"
        elif [ "''${1:-}" = "--tmp-profile" ]; then
          # Одноразовый контейнер: чистый слой на один запуск, стирается, когда
          # из него выйдет ПОСЛЕДНЯЯ программа. Живёт в /tmp (у нас это btrfs на
          # диске, а не tmpfs, поэтому кэш браузера не съест оперативку).
          #
          # --join <каталог> подсаживает ещё одну программу в уже открытый
          # временный контейнер: так Chrome и Telegram могут делить одну разовую
          # сессию. Без него каждый запуск получает свой чистый слой.
          shift
          if [ "''${1:-}" = "--join" ]; then
            shift; profiledir=''${1:?нужен каталог временного контейнера}; shift
            [ -d "$profiledir" ] || { echo "временного контейнера $profiledir уже нет" >&2; exit 1; }
          else
            profiledir=$(mktemp -d /tmp/vpn-profile-XXXXXXXX)
          fi
          profile=$(basename "$profiledir")
          ephemeral=1
        fi
        sbname=""
        if [ "''${1:-}" = "--fs-sandbox" ]; then shift; fssandbox=1
        elif [ "''${1:-}" = "--sandbox" ]; then
          shift; sbname=''${1:?нужно имя песочницы}; shift; fssandbox=1
        fi
        [ "''${1:-}" = "--" ] && shift

        [ $ephemeral -eq 0 ] && [ -n "$profile" ] && [ ! -d "$profiledir" ] && {
          echo "профиля $profile нет — создай: vpn-zone profile create $profile" >&2; exit 1; }

        # --- ЗАЩИТА ОТ «ДУМАЛ, ЧТО ПОД VPN» ---
        # Соль проблемы: у браузеров и мессенджеров один процесс на профиль.
        # Запустил Chrome без VPN, потом его же в зоне — второй процесс находит
        # сокет первого, отдаёт ему «открой окно» и выходит. И вот что делает
        # это опасным: окно ОТКРЫВАЕТСЯ и выглядит совершенно нормально, ничего
        # не падает и не ругается. Просто рисует его старый процесс, в старой
        # сети — то есть человек уверен, что сидит под VPN, а он нет. А вот alacritty так себя не ведёт: у него каждое окно — свой
        # процесс, и две сети рядом работают нормально.
        #
        # Отличить одно от другого заранее нельзя: это свойство программы, а не
        # системы, и списком его не покрыть — именно поэтому здесь ПРЕДУПРЕЖДЕНИЕ
        # с выбором, а не запрет. Кто ведёт себя как alacritty — отмечается
        # галочкой «не спрашивать», и больше вопрос не всплывает.
        #
        # Проверяем в пределах ОДНОГО профиля (основной тоже профиль — ключ
        # __main__): разные профили не пересекаются по сокетам и мешать друг
        # другу не могут.
        # --- ОГРАНИЧЕНИЕ ДОСТУПА К КОМПОЗИТОРУ ---
        # По умолчанию программа запускается через wl-sandbox: композитор
        # перестаёт выдавать ей протоколы слежки (захват экрана, чтение буфера в
        # фоне, эмуляция ввода, список чужих окон — проверено, 47 протоколов
        # против 33). Обычная работа не страдает: свои окна, ввод в них, буфер по
        # Ctrl+C/Ctrl+V, GPU и звук остаются.
        #
        # Исключения нужны тем, кто этими протоколами и живёт: скриншотилкам,
        # менеджеру буфера, записи экрана. Список правится в
        # ~/.config/vpn-zones/wayland-allow, по программе на строку.
        wlmode=$(cat "${config.home.homeDirectory}/.config/vpn-zones/wayland-sandbox" 2>/dev/null || echo on)
        allowfile="${config.home.homeDirectory}/.config/vpn-zones/wayland-allow"
        appbin="''${VPN_ZONE_APPID:-}"
        if [ -z "$appbin" ]; then
          for w in "$@"; do
            case "$w" in
              env|sh|bash|setsid|nohup|-*) continue ;;
              # Присваивание переменной пропускаем, но ТОЛЬКО настоящее: шаблон
              # «*=*» отбрасывал и обычные аргументы со знаком равенства внутри
              # (например строку скрипта после sh -c), и app-id получался пустым.
              *" "*) appbin=$(basename "$w"); break ;;
              [A-Za-z_]*=*) continue ;;
              *) appbin=$(basename "$w"); break ;;
            esac
          done
        fi
        # Идентификатор уходит в аргумент wl-sandbox, поэтому он ОБЯЗАН быть
        # одним словом: пробелы разваливали его на два аргумента, и запускалась
        # не та программа. Проверено на `sh -c 'echo …'`.
        # tr -d перед обрезкой обязателен: у многострочной команды первая
        # строка пустая, cut отдавал пустоту, и запуск падал с «нужен app-id».
        appbin=$(printf '%s' "$appbin" | tr -d '\n' | tr -c 'A-Za-z0-9_.-' '_' | cut -c1-64)
        if [ "$wlmode" = "on" ] && [ -n "$appbin" ]; then
          allowed=0
          case "$appbin" in
            grim|slurp|swappy|wl-copy|wl-paste|copyq|wf-recorder|obs|obs-studio|\
            spectacle|ksnip|wtype|ydotool|niri|noctalia|noctalia-shell|waybar|\
            wayland-info|wlr-randr|kanshi|gammastep|wlsunset|wdisplays|\
            flatpak|bwrap|podman|distrobox)
              # flatpak и прочие песочницы исключены НЕ по недосмотру: они
              # создают security-context сами, а у ограниченного клиента этот
              # протокол как раз отобран — вложить одну песочницу в другую не
              # выйдет. Их собственная изоляция строже нашей, так что пусть
              # работают своим механизмом.
              allowed=1 ;;
          esac
          if [ -f "$allowfile" ] && grep -qxF "$appbin" "$allowfile" 2>/dev/null; then
            allowed=1
          fi
          [ $allowed -eq 0 ] && set -- ${wl-sandbox}/bin/wl-sandbox "$appbin" "$@"
        fi

        # Песочница файловой системы — ТОЛЬКО по явному флагу. Включать её всем
        # подряд нельзя: программа теряет доступ к своим привычным каталогам, и
        # что именно ей нужно, выясняется поштучно.
        if [ $fssandbox -eq 1 ]; then
          # Идентификатор берём тот же, что у пикера (id ярлыка), и только при
          # его отсутствии — имя бинаря. Иначе разрешения двоятся: у Discord
          # ярлык даёт «discord», а бинарь называется «Discord», и получались
          # два независимых набора доступов на одну программу.
          fsid=''${VPN_ZONE_APPID:-$appbin}
          if [ -n "$sbname" ]; then
            set -- ${vpn-fs-sandbox}/bin/vpn-fs-sandbox "$fsid" --name "$sbname" -- "$@"
          else
            set -- ${vpn-fs-sandbox}/bin/vpn-fs-sandbox "$fsid" -- "$@"
          fi
        fi

        pkey=''${profile:-__main__}
        [ $ephemeral -eq 1 ] && pkey="$profile"
        appname=$(basename "''${1:-программа}")
        regdir="$root/.running/$pkey"
        mkdir -p "$regdir"
        reg="$regdir/''${VPN_ZONE_APPID:-$appname}"
        busy=""
        if [ -f "$reg" ]; then
          # Мёртвые записи выбрасываем на лету: файл переписывается только
          # живыми. Перепись — под flock: два одновременных запуска одной
          # программы делали read→rewrite→mv без блокировки и теряли записи
          # друг друга. Строку добавляем printf'ом — многострочная переменная
          # с закрывающей кавычкой в нулевой колонке сбила бы снятие общего
          # отступа в Nix-строке и разломала бы heredoc справки выше.
          # Третье поле (выбранный контейнер) в сравнение зоны не входит:
          # раньше `read -r pid z` склеивал зону с выбором, и «та же зона, но
          # с песочницей» ложно считалась чужой сетью.
          busy=$(
            (
              flock 9
              : > "$reg.new"
              b=""
              while read -r pid z sel; do
                [ -n "''${pid:-}" ] || continue
                [ -d "/proc/$pid" ] || continue
                printf '%s %s %s\n' "$pid" "$z" "$sel" >> "$reg.new"
                [ "$z" = "$name" ] || b="$z"
              done < "$reg"
              mv "$reg.new" "$reg"
              printf '%s' "$b"
            ) 9>>"$regdir/.lock"
          )
        fi
        if [ -n "$busy" ] && [ -z "''${VPN_ZONE_DRYRUN:-}" ]; then
          msg=$(printf '«%s» уже запущена в сети «%s», а ты открываешь её в «%s».\n\nОсторожно: у программ с одним процессом на профиль (браузеры, Telegram, Discord) окно ОТКРОЕТСЯ и будет выглядеть обычно — но нарисует его старый процесс, и трафик в нём пойдёт через «%s», а не через «%s». Со стороны неотличимо, поэтому и предупреждаем.\n\nЕсли у программы каждое окно своё (терминалы, редакторы), всё в порядке — отметь «не спрашивать снова».' \
            "$appname" "$busy" "$name" "$busy" "$name")
          if [ -n "''${WAYLAND_DISPLAY:-}''${DISPLAY:-}" ]; then
            ${kdialog} --title "Программа уже запущена в другой сети" \
              --dontagain "vpn-zonesrc:conflict-$appname" \
              --warningcontinuecancel "$msg" 2>/dev/null || exit 0
          else
            # Из терминала диалог показать негде: предупреждаем и продолжаем —
            # молча отменять запуск здесь было бы хуже, чем предупредить.
            echo "$msg" >&2
          fi
        fi
        p=$(zone_pid "$name" || true)
        if [ -z "''${p:-}" ]; then
          # Ярлык мог быть нажат при опущенной зоне — поднимаем сами, это
          # ожидаемое поведение, а не ошибка.
          systemctl --user start "vpn-zone@$name.service"
          for _ in $(seq 1 100); do [ -f "$root/$name/ready" ] && break; sleep 0.1; done
          p=$(zone_pid "$name" || true)
        fi
        [ -n "''${p:-}" ] || { echo "зона $name не поднимается" >&2; exit 1; }

        # Разделение профилей делает САМА ЗОНА, накладывая overlayfs на
        # XDG-каталоги (см. zone-init). Поэтому здесь ничего к команде
        # дописывать не нужно: работает для любой программы, независимо от того,
        # какие флаги она понимает. Прежняя таблица флагов (--user-data-dir и
        # компания) убрана — она требовала знать каждую программу поимённо.

        # Отладочный выхлоп: показать итоговую команду, ничего не запуская.
        if [ -n "''${VPN_ZONE_DRYRUN:-}" ]; then
          echo "зона $name, профиль ''${profile:-основной}: $*"
          exit 0
        fi

        # Отмечаемся в реестре: $$ переживёт exec (PID не меняется), поэтому
        # запись остаётся верной всё время работы программы, а мёртвые чистятся
        # при следующем запуске.
        #
        # Третьим полем — ЧТО было выбрано. Без него повторный клик по ярлыку
        # уже запущенной программы возвращал её «голой»: сеть из реестра бралась,
        # а песочница терялась, потому что при песочнице profile пуст и ключ
        # каталога всегда получался __main__.
        if [ -n "$sbname" ]; then selector="sb:$sbname"
        elif [ $fssandbox -eq 1 ]; then selector="__fs__"
        else selector=''${profile:-}
        fi
        # Под тем же flock: без него запись могла попасть между чужими
        # read и mv при переписи файла — и молча пропасть. $$ в сабшелле
        # остаётся PID основного процесса, то есть того, кто сделает exec.
        ( flock 9; printf '%s %s %s\n' "$$" "$name" "$selector" >> "$reg" ) 9>>"$regdir/.lock"

        # Метка для потомков: если программа, запущенная в зоне, попробует
        # открыть что-то ещё (ссылку из мессенджера, файл из редактора), её
        # запуск будет делегирован наружу — см. блок в начале `run`.
        export VPN_ZONE_CURRENT="$name"

        if [ -z "$profiledir" ]; then
          # Без профиля — обычный вход в зону, ~/ общий.
          exec nsenter --preserve-credentials -U -n -m -t "$p" -- "$@"
        fi

        # С профилем: --keep-caps оставляет права, полученные при входе в
        # user-namespace зоны (без него CapEff обнуляется и смонтировать слой
        # нечем), затем свой mount namespace на этот запуск, и уже внутри
        # накладываются слои профиля. Права снимаются перед стартом программы —
        # см. крейт rust/, модуль profile.
        exec nsenter --preserve-credentials --keep-caps -U -n -m -t "$p" -- \
          unshare --mount --propagation private -- \
          ${vpn-zone-rust}/bin/vpn-zone-core profile-run \
            "$profiledir" "$name" "$ephemeral" "$regdir" -- "$@"
        ;;
      gc)
        # Уборка зависших наборов «unshare + sleep + pasta». Критерии намеренно
        # ТОЧНЫЕ, а не «убить всё осиротевшее»: первая версия этой команды
        # погасила живую зону, потому что смотрела только на zone.pid.
        #
        #   • процессы под systemd (vpn-zone@…) не трогаем вовсе — ими управляет
        #     юнит, и если что-то не так, это его дело;
        #   • pasta гасим, только если netns, который она обслуживает, мёртв —
        #     номер процесса виден прямо в её командной строке;
        #   • чужие песочницы (bwrap) не трогаем: в них работают программы.
        killed=0
        for pid in $(pgrep -x pasta 2>/dev/null || true); do
          cg=$(cat "/proc/$pid/cgroup" 2>/dev/null || true)
          case "$cg" in *vpn-zone@*) continue ;; esac
          target=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null \
            | grep -oE '/proc/[0-9]+/ns/net' | head -1 | cut -d/ -f3)
          [ -n "''${target:-}" ] || continue
          [ -d "/proc/$target" ] && continue
          kill "$pid" 2>/dev/null && killed=$((killed + 1))
        done
        # Мёртвые записи «кто где запущен» — под тем же flock, что и запись:
        # без него gc мог прочитать файл до чужого printf и стереть свежую
        # запись только что стартовавшей программы.
        cleaned=0
        for f in "$root"/.running/*/*; do
          [ -f "$f" ] || continue
          if (
            flock 9
            while read -r rp _; do
              [ -n "''${rp:-}" ] && [ -d "/proc/$rp" ] && exit 1
            done < "$f"
            rm -f "$f"
          ) 9>>"$(dirname "$f")/.lock"; then
            cleaned=$((cleaned + 1))
          fi
        done
        # Брошенные одноразовые контейнеры: их дом стирается за последним
        # жильцом, но при жёстком убийстве каталог остаётся. Судим по живым
        # PID в реестре, а не по существованию его каталога: после жёсткого
        # убийства каталог реестра остаётся лежать с мёртвыми записями, и
        # прежняя проверка держала мусор в /tmp вечно.
        for d in /tmp/vpn-profile-*; do
          [ -d "$d" ] || continue
          n=$(basename "$d")
          live=0
          for f in "$root/.running/$n"/*; do
            [ -f "$f" ] || continue
            while read -r rp _; do
              [ -n "''${rp:-}" ] && [ -d "/proc/$rp" ] && { live=1; break; }
            done < "$f"
            [ $live -eq 1 ] && break
          done
          [ $live -eq 1 ] && continue
          rm -rf "$d" "$root/.running/$n"
          cleaned=$((cleaned + 1))
        done
        echo "остановлено зависших выходов в сеть: $killed, подчищено записей: $cleaned"
        ;;
      perms)
        # Доступы спрашиваются один раз на программу и запоминаются. Отсюда их
        # видно и можно сбросить, чтобы диалог появился снова.
        pdir="${config.home.homeDirectory}/.config/vpn-zones/fs-perms"
        sub=''${1:-list}; [ $# -gt 0 ] && shift || true
        case "$sub" in
          list)
            if [ -d "$pdir" ] && [ -n "$(ls -A "$pdir" 2>/dev/null)" ]; then
              for f in "$pdir"/*; do
                [ -f "$f" ] || continue
                v=$(tr '\n' ' ' < "$f")
                echo "$(basename "$f") → ''${v:-ничего}"
              done
            else
              echo "доступы никому не выдавались"
            fi
            ;;
          reset)
            what=''${1:?имя программы или --all}
            if [ "$what" = "--all" ]; then
              rm -rf "''${pdir:?}"; echo "сброшено для всех — при следующем запуске спросит заново"
            else
              rm -f "''${pdir:?}/$what"; echo "сброшено для $what"
            fi
            ;;
          *) echo "vpn-zone perms list|reset <программа|--all>" >&2; exit 1 ;;
        esac
        ;;
      sandbox)
        # Песочницы — это НЕ контейнеры: у контейнера слой поверх твоего дома
        # (видно всё, разведены только данные), у песочницы дом свой и пустой,
        # а наружу торчит лишь разрешённое. Потому и хранятся отдельно.
        sbroot="${config.home.homeDirectory}/.local/state/vpn-sandboxes"
        sub=''${1:-list}; [ $# -gt 0 ] && shift || true
        case "$sub" in
          create)
            sname=''${1:?нужно имя песочницы}
            case "$sname" in
              */*|*" "*|-*|.*) echo "в имени нельзя: / пробел, и оно не должно начинаться с - или ." >&2; exit 1 ;;
            esac
            mkdir -p "$sbroot/$sname/home"
            echo "песочница $sname создана (свой пустой дом, доступ наружу спросится при запуске)"
            ;;
          list)
            if [ -d "$sbroot" ] && [ -n "$(ls -A "$sbroot" 2>/dev/null)" ]; then
              for d in "$sbroot"/*/; do
                sn=$(basename "$d")
                perms=$(cat "$d/perms" 2>/dev/null | tr '\n' ' ')
                case "$sn" in
                  app-*) echo "$sn — своя песочница программы ''${sn#app-}, $(du -sh "$d" 2>/dev/null | cut -f1), доступ: ''${perms:-ничего}" ;;
                  *) echo "$sn — $(du -sh "$d" 2>/dev/null | cut -f1), доступ: ''${perms:-ничего}" ;;
                esac
              done
            else
              echo "песочниц нет. Создать: vpn-zone sandbox create <имя>"
            fi
            ;;
          rm)
            sname=''${1:?нужно имя песочницы}
            [ -d "$sbroot/$sname" ] || { echo "песочницы $sname нет" >&2; exit 1; }
            rm -rf "''${sbroot:?}/$sname"
            echo "песочница $sname удалена вместе со своим домом"
            ;;
          *) echo "vpn-zone sandbox create|list|rm <имя>" >&2; exit 1 ;;
        esac
        ;;
      profile)
        sub=''${1:-list}; [ $# -gt 0 ] && shift || true
        case "$sub" in
          create)
            pname=''${1:?нужно имя профиля}
            # Раньше разрешалась только латиница, и GUI, санитизируя ввод,
            # превращал русское название в строку дефисов. Такое имя ломает
            # kdialog: аргумент, начинающийся с «-», он принимает за опцию и
            # молча закрывается. Теперь запрещаем ровно опасное: разделители
            # пути, пробелы и ведущий дефис/точку.
            case "$pname" in
              */*|*" "*|-*|.*) echo "в имени нельзя: / пробел, и оно не должно начинаться с - или ." >&2; exit 1 ;;
            esac
            mkdir -p "$profiles/$pname"
            echo "профиль $pname создан (пустой слой поверх твоего ~/)"
            ;;
          list)
            if [ -d "$profiles" ] && [ -n "$(ls -A "$profiles" 2>/dev/null)" ]; then
              for d in "$profiles"/*/; do
                pn=$(basename "$d"); where=""
                # Кто и где сейчас открыт — из общего реестра запусков
                # ($root/.running/<профиль>/<программа>), тот же, по которому
                # ловится конфликт сетей.
                for f in "$root/.running/$pn"/*; do
                  [ -f "$f" ] || continue
                  while read -r pid z _; do
                    [ -n "''${pid:-}" ] && [ -d "/proc/$pid" ] && { where="$z"; break; }
                  done < "$f"
                  [ -n "$where" ] && break
                done
                size=$(du -sh "$d" 2>/dev/null | cut -f1)
                if [ -n "$where" ]; then echo "$pn — открыт в сети $where ($size)"
                else echo "$pn — свободен ($size)"; fi
              done
            else
              echo "профилей нет. Создать: vpn-zone profile create <имя>"
            fi
            ;;
          rm)
            pname=''${1:?нужно имя профиля}
            [ -d "$profiles/$pname" ] || { echo "профиля $pname нет" >&2; exit 1; }
            rm -rf "''${profiles:?}/$pname"
            echo "профиль $pname удалён"
            ;;
          *) echo "vpn-zone profile create|list|rm <имя>" >&2; exit 1 ;;
        esac
        ;;
      wayland-sandbox)
        v=''${1:?on или off}
        case "$v" in on|off) ;; *) echo "только on или off" >&2; exit 1;; esac
        mkdir -p "${config.home.homeDirectory}/.config/vpn-zones"
        printf '%s' "$v" > "${config.home.homeDirectory}/.config/vpn-zones/wayland-sandbox"
        if [ "$v" = "on" ]; then
          echo "программы запускаются без доступа к захвату экрана, буферу в фоне и эмуляции ввода"
        else
          echo "ограничение снято: программы снова получают полный набор протоколов композитора"
        fi
        ;;
      isolate)
        v=''${1:?overlay или off}
        case "$v" in overlay|off) ;; *) echo "только overlay или off" >&2; exit 1;; esac
        mkdir -p "${config.home.homeDirectory}/.config/vpn-zones"
        printf '%s' "$v" > "${config.home.homeDirectory}/.config/vpn-zones/isolate"
        if [ "$v" = "overlay" ]; then
          echo "зоны накладывают свой слой на ~/.config, ~/.local/share, ~/.cache,"
          echo "~/.mozilla, ~/.pki — программа видит настройки, но пишет в слой зоны"
        else
          echo "зоны используют общий профиль. Учти: браузер тогда откроет окно"
          echo "в уже запущенном процессе, и трафик пойдёт мимо VPN"
        fi
        echo "поднятые зоны надо перезапустить, чтобы это применилось"
        ;;
      reset-profile)
        # Слой зоны разрастается (кэш браузера, куки) — вот кнопка «начать с
        # чистого листа», не трогая основной профиль.
        name=''${1:?нужно имя зоны}
        [ -d "$root/$name" ] || { echo "зоны $name нет" >&2; exit 1; }
        if [ -n "$(zone_pid "$name" || true)" ]; then
          echo "сначала опусти зону: vpn-zone down $name" >&2; exit 1
        fi
        rm -rf "''${root:?}/$name/overlay"
        echo "слой профиля зоны $name очищен (основной профиль не тронут)"
        ;;
      rm)
        name=''${1:?нужно имя}
        # direct и offline — встроенные варианты пикера, а не зоны: удалять там
        # нечего (прямой трафик — это отсутствие зоны вовсе, а пустая зона
        # создаётся заново сама при первом же запуске «Без сети»).
        case "$name" in
          direct|offline) echo "«$name» — встроенный вариант, его нельзя удалить" >&2; exit 1;;
        esac
        [ -d "$root/$name" ] || { echo "зоны $name нет" >&2; exit 1; }
        systemctl --user stop "vpn-zone@$name.service" 2>/dev/null || true
        rm -rf "''${root:?}/$name"
        # Снимаем закрепления, которые указывали на эту зону: иначе программа
        # осталась бы намертво привязана к несуществующей сети и молча падала
        # бы при каждом запуске.
        for f in "$root"/.pinned/* "$root"/.last/*; do
          [ -f "$f" ] || continue
          [ "$(cat "$f")" = "$name" ] && rm -f "$f"
        done
        vpn-zone sync
        echo "зона $name удалена"
        ;;
      sync) exec vpn-zone-sync ;;   # из профиля (см. PATH выше) — так нет зависимости по кругу
      mode)
        m=''${1:?режим: picker | per-zone | both | off}
        case "$m" in picker|per-zone|both|off) ;; *) echo "неизвестный режим: $m" >&2; exit 1;; esac
        mkdir -p "${config.home.homeDirectory}/.config/vpn-zones"
        printf '%s' "$m" > "${config.home.homeDirectory}/.config/vpn-zones/mode"
        vpn-zone-sync
        ;;
      default-profile)
        # Контейнер по умолчанию для ВСЕХ запусков. «ask» — спрашивать каждый
        # раз (как было), «main» — всегда основной без вопроса, иначе имя
        # профиля. Вопрос о сети это не отменяет.
        v=''${1:?ask | main | own | <имя профиля>}
        case "$v" in
          ask|main|own) ;;
          *) [ -d "$profiles/$v" ] || { echo "профиля $v нет" >&2; exit 1; } ;;
        esac
        mkdir -p "${config.home.homeDirectory}/.config/vpn-zones"
        printf '%s' "$v" > "${config.home.homeDirectory}/.config/vpn-zones/default-profile"
        echo "контейнер по умолчанию: $v"
        ;;
      default)
        v=''${1:?вариант: offline | direct | <имя зоны>}
        mkdir -p "${config.home.homeDirectory}/.config/vpn-zones"
        printf '%s' "$v" > "${config.home.homeDirectory}/.config/vpn-zones/default"
        echo "по умолчанию в пикере: $v"
        ;;
      pins)
        found=0
        for f in "$root"/.pinned/* "$root"/.pinnedprofile/*; do
          [ -f "$f" ] || continue
          k=$(basename "$f")
          nm=$(cat "$root/.labels/$k" 2>/dev/null || echo "$k")
          if [ "$(dirname "$f")" = "$root/.pinned" ]; then
            echo "$nm: сеть → $(cat "$f")"
          else
            v=$(cat "$f"); [ "$v" = "__main__" ] && v="основной"
            echo "$nm: контейнер → $v"
          fi
          found=1
        done
        [ $found -eq 1 ] || echo "закреплённых программ нет — пикер спрашивает каждый раз"
        ;;
      forget)
        what=''${1:?имя программы или --all}
        if [ "$what" = "--all" ]; then
          rm -rf "''${root:?}/.pinned" "''${root:?}/.last" "''${root:?}/.lastprofile" \
            "''${root:?}/.pinnedprofile"
          echo "сброшено для всех программ"
        else
          rm -f "''${root:?}/.pinned/$what" "''${root:?}/.last/$what" \
            "''${root:?}/.lastprofile/$what" "''${root:?}/.pinnedprofile/$what"
          echo "сброшено для $what"
        fi
        ;;
      ""|-h|--help|help) usage ;;
      *) echo "неизвестная команда: $cmd" >&2; usage; exit 1 ;;
    esac
  '';

  # --- ЧАСТЬ 3б: ПИКЕР СЕТИ ---
  # Спрашивает при запуске, куда пустить программу. Вызывается из перехваченных
  # ярлыков (режим picker).
  #
  # ТРИ УРОВНЯ ПАМЯТИ, от сильного к слабому:
  #   1. ЗАКРЕПЛЕНИЕ (.pinned/<программа>) — диалога нет вообще, программа сразу
  #      уходит в назначенную сеть. Ставится пунктом «Всегда: …» прямо в меню,
  #      снимается пунктом «Спрашивать снова», ярлыком «Сбросить сети программ»
  #      или командой `vpn-zone forget`.
  #   2. ПОСЛЕДНИЙ ВЫБОР (.last/<программа>) — диалог показывается, но нужный
  #      пункт уже выделен.
  #   3. ОБЩИЙ ДЕФОЛТ (~/.config/vpn-zones/default), по умолчанию «offline».
  #      Это и есть политика «незнакомая программа в интернет не идёт»: пока ты
  #      явно не выбрал сеть, предлагается вариант без неё.
  #
  # Принудительно вызвать диалог при закреплённой программе: VPN_ZONE_ASK=1.
  vpn-zone-pick = pkgs.writeShellScriptBin "vpn-zone-pick" ''
    set -eu
    # Аргументы: [--id <ключ>] [--label <имя>] -- <команда…>
    #
    # --id — стабильный идентификатор ярлыка (имя .desktop без расширения). По
    # нему запоминается выбор сети и контейнера. Без него ключ пришлось бы
    # вычислять из команды, а там сплошь и рядом обёртки: у AyuGram, например,
    # Exec начинается с `env DESKTOPINTEGRATION=1 …`, и ключом становилось «env».
    #
    # Названия программы в аргументах БОЛЬШЕ НЕТ: оно содержало пробелы, а
    # Telegram и подобные разбирают Exec наивно, кавычки не снимая — «Zen
    # Browser» разваливался на два аргумента, и запуск падал. Имя берётся из
    # файла меток, который пишет генератор ярлыков.
    appid=""; label=""
    # Совместимость со старыми ярлыками, где имя шло первым аргументом. Ярлыки и
    # пикер обновляются НЕ атомарно: при пересборке sync успел отработать раньше
    # подмены профиля, и новый пикер получил ярлыки старого формата — AyuGram
    # перестал запускаться вовсе («невозможно выполнить AyuGram Desktop»).
    # Разбирать оба формата дешевле, чем полагаться на порядок обновления.
    # Метку принимаем, только если дальше есть «--»: иначе съели бы команду.
    case "''${1:-}" in
      -*|"") ;;
      *) if printf '%s\n' "$@" | ${pkgs.gnugrep}/bin/grep -qx -- '--'; then
           label=$1; shift
         fi ;;
    esac
    while :; do
      case "''${1:-}" in
        --id) shift; appid=''${1:-}; shift || true ;;
        --label) shift; label=''${1:-}; shift || true ;;
        --) shift; break ;;
        *) break ;;
      esac
    done
    [ $# -gt 0 ] || { echo "нечего запускать" >&2; exit 1; }

    root="${stateDir}"
    cfg="${config.home.homeDirectory}/.config/vpn-zones"
    ${pkgs.coreutils}/bin/mkdir -p "$root/.last" "$root/.lastprofile" "$root/.pinned" "$root/.pinnedprofile" "$root/.labels" "$cfg"
    vpnzone=${config.home.profileDirectory}/bin/vpn-zone

    if [ -n "$appid" ]; then
      key=$(printf '%s' "$appid" | ${pkgs.gnused}/bin/sed 's/[^a-zA-Z0-9_.-]/_/g')
    else
      # Запасной разбор — для запусков мимо ярлыка (бинды niri, терминал):
      # пропускаем обёртки и присваивания переменных, берём первую настоящую
      # команду.
      key=""
      for w in "$@"; do
        case "$w" in
          env|sh|bash|setsid|nohup|systemd-run) continue ;;
          -*) continue ;;
          *" "*) key=$(${pkgs.coreutils}/bin/basename "$w"); break ;;
          [A-Za-z_]*=*) continue ;;
          *) key=$(${pkgs.coreutils}/bin/basename "$w"); break ;;
        esac
      done
      key=$(printf '%s' "''${key:-программа}" | ${pkgs.gnused}/bin/sed 's/[^a-zA-Z0-9_.-]/_/g')
    fi
    # Имя для диалогов: из метки, оставленной генератором ярлыков, иначе из
    # --label, иначе сам ключ.
    if [ -z "$label" ]; then
      label=$(${pkgs.coreutils}/bin/cat "$root/.labels/$key" 2>/dev/null || echo "$key")
    else
      printf '%s' "$label" > "$root/.labels/$key"
    fi

    cmd=( "$@" )
    fssand=0
    sandbox=""

    # Профиль — ВТОРОЙ вопрос, и задаётся он ВСЕГДА, даже когда профилей ещё нет.
    # Сначала диалог показывался только при наличии профилей, и получалось, что
    # про них невозможно узнать, не читая справку: система молча решала за тебя,
    # что контейнер не нужен. Поэтому пункт «Основной» есть всегда, а рядом —
    # «Новый профиль…», чтобы завести контейнер прямо отсюда.
    ask_profile() {
      profile=""
      # Глобальный выбор «не спрашивать»: main — всегда основной, имя профиля —
      # всегда он. Настраивается ярлыком «Настройки VPN-зон» или командой
      # `vpn-zone default-profile`.
      local defp
      defp=$(${pkgs.coreutils}/bin/cat "$cfg/default-profile" 2>/dev/null || echo ask)
      case "$defp" in
        ask) ;;
        main) profile=""; return 0 ;;
        own) sandbox="app-$key"; fssand=1; profile=""; return 0 ;;
        *) if [ -d "${profilesDir}/$defp" ]; then profile=$defp; return 0; fi ;;
      esac
      local pmenu=( "" "Основной (общий с системой)" pinmain "Основной — всегда" )
      # Песочница файлов — не контейнер, а отдельное свойство запуска, но
      # спрашивать про неё третьим диалогом было бы утомительно: кладём сюда же.
      # Своя песочница программы: постоянный дом, но только её собственный.
      # Отличается от именованной лишь тем, что имя берётся автоматически, —
      # то есть это «изолированный профиль по умолчанию», который потом можно
      # объединить с другой программой, выбрав общую именованную песочницу.
      pmenu+=( __ownsb__ "🔒 Своя песочница: постоянный дом только этой программы" )
      pmenu+=( pin:__ownsb__ "🔒 Своя песочница — всегда" )
      pmenu+=( __fs__ "🔒 Разовая песочница: стирается при выходе" )
      pmenu+=( pin:__fs__ "🔒 Разовая песочница — всегда" )
      # Именованные песочницы: дом общий для всех программ, запущенных в одной и
      # той же, — так две программы могут работать вместе, не видя твоих файлов.
      for d in "${config.home.homeDirectory}/.local/state/vpn-sandboxes"/*/; do
        [ -d "$d" ] || continue
        local sn; sn=$(${pkgs.coreutils}/bin/basename "$d")
        case "$sn" in -*) continue ;; esac
        pmenu+=( "sb:$sn" "🔒 Песочница «$sn»" )
        pmenu+=( "pin:sb:$sn" "🔒 Песочница «$sn» — всегда" )
      done
      pmenu+=( __newsb__ "🔒➕ Новая песочница…" )
      for d in "${profilesDir}"/*/; do
        [ -d "$d" ] || continue
        local pn; pn=$(${pkgs.coreutils}/bin/basename "$d")
        # Имя, начинающееся с дефиса, kdialog принимает за опцию и закрывается
        # без единого слова. Новые такие имена создать уже нельзя, но каталог мог
        # остаться от прежней версии — просто не показываем его.
        case "$pn" in -*) continue ;; esac
        local where=""
        if [ -f "$d/inuse" ]; then
          while read -r pid z _; do
            [ -n "''${pid:-}" ] && [ -d "/proc/$pid" ] && { where="$z"; break; }
          done < "$d/inuse"
        fi
        if [ -n "$where" ] && [ "$where" != "$choice" ]; then
          pmenu+=( "$pn" "$pn — занят сетью $where" )
        else
          pmenu+=( "$pn" "$pn" )
        fi
        pmenu+=( "pin:$pn" "$pn — всегда" )
      done
      # Уже открытые временные контейнеры — чтобы подсадить программу к тем,
      # что сейчас работают (общая разовая сессия), а не заводить ещё один.
      for rd in "$root"/.running/vpn-profile-*/; do
        [ -d "$rd" ] || continue
        local tname; tname=$(${pkgs.coreutils}/bin/basename "$rd")
        [ -d "/tmp/$tname" ] || continue
        local who=""
        for f in "$rd"*; do
          [ -f "$f" ] || continue
          while read -r pid z; do
            [ -n "''${pid:-}" ] && [ -d "/proc/$pid" ] && who="$who $(${pkgs.coreutils}/bin/basename "$f")"
            break
          done < "$f"
        done
        [ -n "$who" ] && pmenu+=( "tmpjoin:/tmp/$tname" "🗑 К открытому временному:''${who}" )
      done
      pmenu+=( "__tmp__" "🗑 Новый временный (сотрётся, когда выйдет последняя программа)" )
      pmenu+=( "__new__" "➕ Новый профиль…" )
      [ -n "''${pinnedprof:-}" ] && pmenu+=( unpinprof "↺ Спрашивать контейнер снова" )

      profile=$(${kdialog} --title "Профиль для «$label»" \
        --default "''${lastprofile:-}" \
        --menu "В каком профиле открыть? Профиль хранит настройки, сессии и логины отдельно от системных" \
        "''${pmenu[@]}" 2>/dev/null) || exit 0

      case "$profile" in
        __fs__) fssand=1; profile=""; return 0 ;;
        __ownsb__) sandbox="app-$key"; fssand=1; profile=""; return 0 ;;
        pin:__ownsb__)
          printf 'sb:app-%s' "$key" > "$root/.pinnedprofile/$key"
          sandbox="app-$key"; fssand=1; profile=""; return 0 ;;
        __newsb__)
          local sname
          sname=$(${kdialog} --title "Новая песочница" \
            --inputbox "Название песочницы. У неё будет свой пустой дом, общий для всех программ, которые ты в ней запустишь." "" 2>/dev/null) || exit 0
          sname=$(printf '%s' "$sname" | ${pkgs.gnused}/bin/sed -e 's#[/"'"'"'`\\]#_#g' -e 's/ /_/g' -e 's/^[-.]*//')
          [ -n "$sname" ] || { profile=""; return 0; }
          "$vpnzone" sandbox create "$sname" >/dev/null 2>&1
          sandbox=$sname; fssand=1; profile=""; return 0 ;;
        sb:*) sandbox=''${profile#sb:}; fssand=1; profile=""; return 0 ;;
        pin:sb:*)
          sandbox=''${profile#pin:sb:}
          printf 'sb:%s' "$sandbox" > "$root/.pinnedprofile/$key"
          fssand=1; profile=""; return 0 ;;
        pin:__fs__)
          printf '__fs__' > "$root/.pinnedprofile/$key"
          fssand=1; profile=""; return 0 ;;
        __tmp__|tmpjoin:*) return 0 ;;
        pinmain)
          # «Основной — всегда»: закрепляем отдельно от сети.
          printf '__main__' > "$root/.pinnedprofile/$key"
          profile=""; return 0 ;;
        pin:*)
          profile=''${profile#pin:}
          printf '%s' "$profile" > "$root/.pinnedprofile/$key"
          return 0 ;;
      esac
      if [ "$profile" = "unpinprof" ]; then
        ${pkgs.coreutils}/bin/rm -f "$root/.pinnedprofile/$key"
        profile=""
        return 0
      fi
      if [ "$profile" = "__new__" ]; then
        local pname
        pname=$(${kdialog} --title "Новый профиль" \
          --inputbox "Название профиля (буквы, цифры, дефис):" "" 2>/dev/null) || exit 0
        # Чистим только то, что реально мешает (пути, пробелы, кавычки), и
        # срезаем ведущие дефисы — кириллица остаётся кириллицей.
        pname=$(printf '%s' "$pname" | ${pkgs.gnused}/bin/sed -e 's#[/"'"'"'`\\]#_#g' -e 's/ /_/g' -e 's/^[-.]*//')
        [ -n "$pname" ] || { profile=""; return 0; }
        "$vpnzone" profile create "$pname" >/dev/null 2>&1
        profile=$pname
      fi
    }

    launch() {
      # Ключ ярлыка — он же app-id для ограничения доступа к композитору.
      export VPN_ZONE_APPID="$key"
      set -- "''${cmd[@]}"
      case "$choice" in
        direct)
          # Изнутри зоны «прямой» получился бы не прямым: процесс унаследовал бы
          # её сеть. Просим systemd запустить снаружи (подробности — в `run`).
          if [ -n "''${VPN_ZONE_CURRENT:-}" ]; then
            exec ${pkgs.systemd}/bin/systemd-run --user --quiet --collect -- "$@"
          fi
          exec "$@" ;;
        offline)
          # Зона без сети создаётся по требованию — держать её в конфиге
          # незачем, это просто пустой namespace.
          [ -d "$root/offline" ] || { ${pkgs.coreutils}/bin/mkdir -p "$root/offline"; : > "$root/offline/offline"; }
          zone=offline ;;
        *) zone=$choice ;;
      esac
      # fsflag заполняется ДО ветки tmpjoin: раньше она читала массив до его
      # инициализации, и живо это было только милостью bash ≥ 4.4, где пустой
      # "''${arr[@]}" под set -u перестал быть ошибкой.
      fsflag=()
      if [ -n "''${sandbox:-}" ]; then
        fsflag=( --sandbox "$sandbox" )
      elif [ "''${fssand:-0}" = "1" ]; then
        fsflag=( --fs-sandbox )
      fi
      case "''${profile:-}" in
        tmpjoin:*)
          exec "$vpnzone" run "$zone" --tmp-profile --join "''${profile#tmpjoin:}" "''${fsflag[@]}" -- "$@" ;;
      esac
      if [ "''${profile:-}" = "__tmp__" ]; then
        exec "$vpnzone" run "$zone" --tmp-profile "''${fsflag[@]}" -- "$@"
      elif [ -n "''${profile:-}" ]; then
        exec "$vpnzone" run "$zone" --profile "$profile" "''${fsflag[@]}" -- "$@"
      else
        exec "$vpnzone" run "$zone" "''${fsflag[@]}" -- "$@"
      fi
    }

    # --- УЖЕ ЗАПУЩЕНА? ТОГДА НИЧЕГО НЕ СПРАШИВАЕМ ---
    # Клик по ярлыку у работающей программы (Discord в трее, например) — это
    # «разверни окно», а не «запусти заново». Спрашивать тут сеть бессмысленно:
    # программа с одним процессом на профиль всё равно отдаст команду уже
    # запущенному экземпляру, и он останется в своей сети. Поэтому находим, где
    # она работает, и запускаем туда же — окно развернётся, а диалога не будет.
    for rd in "$root"/.running/*/; do
      [ -d "$rd" ] || continue
      f="$rd$key"
      [ -f "$f" ] || continue
      while read -r rpid rzone rsel; do
        [ -n "''${rpid:-}" ] || continue
        [ -d "/proc/$rpid" ] || continue
        running_zone=$rzone
        running_sel=''${rsel:-}
        break
      done < "$f"
      [ -n "''${running_zone:-}" ] && break
    done
    if [ -n "''${running_zone:-}" ] && [ -z "''${VPN_ZONE_ASK:-}" ]; then
      choice=$running_zone
      case "''${running_sel:-}" in
        "") profile="" ;;
        __fs__) profile=""; fssand=1 ;;
        sb:*) profile=""; fssand=1; sandbox=''${running_sel#sb:} ;;
        *) profile=$running_sel ;;
      esac
      launch
    fi

    # --- ЗАКРЕПЛЕНИЯ: СЕТЬ И КОНТЕЙНЕР ПОРОЗНЬ ---
    # Сначала закрепление хранило пару «сеть+контейнер», и выбор «Всегда» в
    # первом окне намертво фиксировал заодно и второе. Это неверно: сеть и
    # контейнер — независимые оси, и закреплять хочется то одну, то другую.
    # Теперь два отдельных файла: .pinned (сеть) и .pinnedprofile (контейнер).
    # Диалог показывается только для той оси, которая НЕ закреплена; если
    # закреплены обе — не показывается вовсе.
    #
    # Значение __main__ в .pinnedprofile означает «всегда основной»: пустая
    # строка тут не годится, её не отличить от «не закреплено».
    pinned=$(${pkgs.coreutils}/bin/cat "$root/.pinned/$key" 2>/dev/null || true)
    case "''${pinned:-}" in
      ""|direct|offline) ;;
      *) [ -f "$root/$pinned/config.conf" ] || {
           ${pkgs.coreutils}/bin/rm -f "$root/.pinned/$key"
           pinned=""
         } ;;
    esac
    pinnedprof=$(${pkgs.coreutils}/bin/cat "$root/.pinnedprofile/$key" 2>/dev/null || true)
    case "''${pinnedprof:-}" in
      ""|__main__|__fs__) ;;
      *) [ -d "${profilesDir}/$pinnedprof" ] || {
           ${pkgs.coreutils}/bin/rm -f "$root/.pinnedprofile/$key"
           pinnedprof=""
         } ;;
    esac

    lastprofile=$(${pkgs.coreutils}/bin/cat "$root/.lastprofile/$key" 2>/dev/null || true)
    last=$(${pkgs.coreutils}/bin/cat "$root/.last/$key" 2>/dev/null || true)
    fallback=$(${pkgs.coreutils}/bin/cat "$cfg/default" 2>/dev/null || echo offline)

    # Сеть закреплена — окно сети не показываем. Но тогда и попасть в выбор
    # контейнера было неоткуда: пункт «Сменить контейнер» живёт как раз в том
    # окне. Поэтому если контейнер НЕ закреплён и не задан глобально —
    # спрашиваем его отдельным окном. Так «сеть всегда одна, контейнер каждый
    # раз выбираю» становится возможным.
    asksolo=0
    if [ -n "''${pinned:-}" ] && [ -z "''${VPN_ZONE_ASK:-}" ]; then
      choice=$pinned
      defp_now=$(${pkgs.coreutils}/bin/cat "$cfg/default-profile" 2>/dev/null || echo ask)
      [ -z "''${pinnedprof:-}" ] && [ "$defp_now" = "ask" ] && asksolo=1
    else
      default=''${last:-$fallback}
      nets=( direct "Прямой интернет (без VPN)" offline "Без сети" )
      for d in "$root"/*/; do
        [ -d "$d" ] || continue
        z=$(${pkgs.coreutils}/bin/basename "$d")
        case "$z" in .*|offline) continue;; esac
        [ -f "$d/config.conf" ] || continue
        nets+=( "$z" "VPN: $z" )
      done

      # Меню: сначала «на один раз», следом те же сети с пометкой «Всегда».
      # Одним диалогом вместо двух шагов — закрепление стоит одного клика.
      menu=()
      i=0
      while [ $i -lt ''${#nets[@]} ]; do
        menu+=( "''${nets[$i]}" "''${nets[$((i + 1))]}" )
        i=$((i + 2))
      done
      i=0
      while [ $i -lt ''${#nets[@]} ]; do
        menu+=( "pin:''${nets[$i]}" "Всегда: ''${nets[$((i + 1))]}" )
        i=$((i + 2))
      done
      # Один диалог вместо двух: контейнер по умолчанию берётся прошлый, а
      # сменить его можно этим пунктом. Прежде окна открывались подряд, каждое
      # заново, и экран прыгал — при том что контейнер меняют куда реже сети.
      curp=''${lastprofile:-}
      case "$curp" in
        "") curplabel="основной" ;;
        __fs__) curplabel="разовая песочница" ;;
        sb:app-*) curplabel="своя песочница" ;;
        sb:*) curplabel="песочница ''${curp#sb:}" ;;
        *) curplabel=$curp ;;
      esac
      menu+=( __chooseprofile__ "⚙ Сменить контейнер (сейчас: $curplabel)…" )
      [ -n "''${pinned:-}" ] && menu+=( unpin "↺ Спрашивать сеть снова (закреплено: $pinned)" )

      choice=$(${kdialog} --title "Куда пустить «$label»?" \
        --default "$default" \
        --menu "Выбери сеть для запуска" "''${menu[@]}" 2>/dev/null) || exit 0
      [ -n "''${choice:-}" ] || exit 0

      # Выбрали «сменить контейнер» — спрашиваем его, а потом возвращаемся к
      # выбору сети тем же диалогом.
      if [ "$choice" = "__chooseprofile__" ]; then
        ask_profile
        # Запоминаем ИМЕННО ВЫБОР, а не переменную profile: у песочницы profile
        # пустой (она живёт отдельным флагом), и запись «как есть» превращала её
        # в «основной» — выбор выглядел не сохранившимся.
        sel=''${profile:-}
        [ "''${fssand:-0}" = "1" ] && sel=__fs__
        [ -n "''${sandbox:-}" ] && sel="sb:$sandbox"
        case "$sel" in
          __tmp__|tmpjoin:*) ;;   # одноразовый контейнер помнить незачем
          *) printf '%s' "$sel" > "$root/.lastprofile/$key" ;;
        esac
        exec env VPN_ZONE_ASK=1 "$0" --id "$key" -- "''${cmd[@]}"
      fi

      case "$choice" in
        unpin)
          ${pkgs.coreutils}/bin/rm -f "$root/.pinned/$key"
          exec env VPN_ZONE_ASK=1 "$0" --id "$key" -- "''${cmd[@]}"
          ;;
        pin:*)
          choice=''${choice#pin:}
          printf '%s' "$choice" > "$root/.pinned/$key"
          ;;
      esac
      printf '%s' "$choice" > "$root/.last/$key"
    fi

    # Второй вопрос — контейнер. Он не задаётся, если контейнер закреплён
    # отдельно или задан глобально (`vpn-zone default-profile`).
    if [ "$asksolo" = "1" ]; then
      ask_profile
      sel=''${profile:-}
      [ "''${fssand:-0}" = "1" ] && sel=__fs__
      [ -n "''${sandbox:-}" ] && sel="sb:$sandbox"
      case "$sel" in
        __tmp__|tmpjoin:*) ;;
        *) printf '%s' "$sel" > "$root/.lastprofile/$key" ;;
      esac
    elif [ -n "''${pinnedprof:-}" ] && [ -z "''${VPN_ZONE_ASK:-}" ]; then
      case "$pinnedprof" in
        __main__) profile="" ;;
        __fs__) profile=""; fssand=1 ;;
        sb:*) profile=""; fssand=1; sandbox=''${pinnedprof#sb:} ;;
        *) profile=$pinnedprof ;;
      esac
    else
      # Контейнер не переспрашиваем: берём прошлый выбор (или глобальный
      # дефолт). Сменить — пункт «⚙ Сменить контейнер» в том же окне.
      case "''${lastprofile:-}" in
        "") profile="" ;;
        __fs__) profile=""; fssand=1 ;;
        sb:*) profile=""; fssand=1; sandbox=''${lastprofile#sb:} ;;
        *) [ -d "${profilesDir}/$lastprofile" ] && profile=$lastprofile || profile="" ;;
      esac
      defp=$(${pkgs.coreutils}/bin/cat "$cfg/default-profile" 2>/dev/null || echo ask)
      case "$defp" in
        main) profile="" ;;
        ask) ;;
        own) profile=""; fssand=1; sandbox="app-$key" ;;
        *) [ -d "${profilesDir}/$defp" ] && profile=$defp ;;
      esac
    fi
    launch
  '';

  # --- ЧАСТЬ 3в: СБРОС ЗАКРЕПЛЕНИЙ (ярлык в лаунчере) ---
  vpn-zone-forget-gui = pkgs.writeShellScriptBin "vpn-zone-forget-gui" ''
    set -eu
    root="${stateDir}"
    pins="$root/.pinned"

    if [ -z "$(${pkgs.coreutils}/bin/ls -A "$pins" "$root/.pinnedprofile" 2>/dev/null)" ]; then
      ${kdialog} --msgbox "Закреплённых программ нет — сеть спрашивается при каждом запуске." 2>/dev/null || true
      exit 0
    fi

    menu=( __all__ "⟲ Сбросить у ВСЕХ программ" )
    # Показываем название программы, а не внутренний ключ: ключ — это id ярлыка
    # (com.ayugram.desktop), по нему не догадаешься, о чём речь. Метку пишет сам
    # пикер при запуске, в $root/.labels.
    seen=" "
    for f in "$pins"/* "$root/.pinnedprofile"/*; do
      [ -f "$f" ] || continue
      n=$(${pkgs.coreutils}/bin/basename "$f")
      case "$seen" in *" $n "*) continue ;; esac
      seen="$seen$n "
      nm=$(${pkgs.coreutils}/bin/cat "$root/.labels/$n" 2>/dev/null || echo "$n")
      net=$(${pkgs.coreutils}/bin/cat "$pins/$n" 2>/dev/null || echo "—")
      prof=$(${pkgs.coreutils}/bin/cat "$root/.pinnedprofile/$n" 2>/dev/null || echo "—")
      [ "$prof" = "__main__" ] && prof="основной"
      menu+=( "$n" "$nm — сеть: $net, контейнер: $prof" )
    done

    choice=$(${kdialog} --title "Сбросить сеть по умолчанию" \
      --menu "У какой программы забыть выбранную сеть?" "''${menu[@]}" 2>/dev/null) || exit 0
    [ -n "''${choice:-}" ] || exit 0

    if [ "$choice" = "__all__" ]; then
      ${config.home.profileDirectory}/bin/vpn-zone forget --all >/dev/null
      ${notify} -a "VPN-зоны" -t 5000 "Сброшено" "Сеть снова спрашивается для всех программ."
    else
      ${config.home.profileDirectory}/bin/vpn-zone forget "$choice" >/dev/null
      ${notify} -a "VPN-зоны" -t 5000 "Сброшено" "Для «$choice» сеть снова будет спрашиваться."
    fi
  '';

  # --- ЧАСТЬ 4: генерация ярлыков ---
  # Разбором занимается крейт rust/ (модуль desktop), а не sed: .desktop — это
  # ini с локализованными ключами и экранированием, и разбирать его построчно
  # значит однажды получить ярлык с поехавшим Exec. Здесь остаётся тонкая
  # обёртка, которая подставляет четыре пути.
  # Третий аргумент — путь к vpn-zone, который попадёт в Exec ярлыков. Берём
  # ПРОФИЛЬНЫЙ путь, а не store: во-первых, это разрывает зависимость по кругу
  # (vpn-zone зовёт sync, sync подставляет vpn-zone), во-вторых, ярлыки не
  # протухают при каждом обновлении пакета — иначе после любой пересборки они
  # указывали бы на старый store-путь до следующего sync.
  vpn-zone-sync = pkgs.writeShellScriptBin "vpn-zone-sync" ''
    exec ${vpn-zone-rust}/bin/vpn-zone-core sync \
      "${stateDir}" "${config.home.homeDirectory}" \
      "${config.home.profileDirectory}/bin/vpn-zone" \
      "${config.home.profileDirectory}/bin/vpn-zone-pick"
  '';

  # --- ЧАСТЬ 4б: ГРАФИЧЕСКОЕ УДАЛЕНИЕ ЗОНЫ ---
  # В списке только настоящие зоны. «Прямой интернет» и «Без сети» сюда не
  # попадают намеренно: первое — это отсутствие зоны как таковой, второе —
  # пустой namespace, который создаётся заново при первом же запуске. Удалять
  # там нечего, а пункт в меню только путал бы.
  vpn-zone-remove-gui = pkgs.writeShellScriptBin "vpn-zone-remove-gui" ''
    set -eu
    root="${stateDir}"
    vpnzone=${config.home.profileDirectory}/bin/vpn-zone

    menu=()
    for d in "$root"/*/; do
      [ -d "$d" ] || continue
      z=$(${pkgs.coreutils}/bin/basename "$d")
      case "$z" in .*|offline) continue;; esac
      [ -f "$d/config.conf" ] || continue
      if [ -f "$d/ready" ] && [ -d "/proc/$(${pkgs.coreutils}/bin/cat "$d/zone.pid" 2>/dev/null || echo 0)" ]; then
        menu+=( "$z" "$z (сейчас поднята)" )
      else
        menu+=( "$z" "$z" )
      fi
    done

    if [ ''${#menu[@]} -eq 0 ]; then
      ${kdialog} --msgbox "VPN-зон нет — удалять нечего.\n\nСоздать: «Добавить VPN-зону» в лаунчере." 2>/dev/null || true
      exit 0
    fi

    zone=$(${kdialog} --title "Удалить VPN-зону" \
      --menu "Какую зону удалить?" "''${menu[@]}" 2>/dev/null) || exit 0
    [ -n "''${zone:-}" ] || exit 0

    # Второй шаг обязателен: вместе с зоной стирается копия конфига, а в ней
    # приватный ключ. Восстановить его из зоны потом неоткуда.
    ${kdialog} --title "Точно удалить?" \
      --warningcontinuecancel "Зона «$zone» будет остановлена и удалена вместе с копией конфига (там приватный ключ).\n\nПрограммы, закреплённые за этой зоной, снова начнут спрашивать сеть." \
      2>/dev/null || exit 0

    if out=$("$vpnzone" rm "$zone" 2>&1); then
      ${notify} -a "VPN-зоны" -t 6000 "Зона «$zone» удалена" "Ярлыки пересобраны."
    else
      ${kdialog} --error "Не удалось удалить зону «$zone»:\n$out" 2>/dev/null || true
    fi
  '';

  # --- ЧАСТЬ 4в: ГРАФИЧЕСКОЕ УДАЛЕНИЕ ПРОФИЛЕЙ ---
  # Профиль — это накопленный слой поверх твоего ~/: кэш браузера, куки, сессии.
  # Он разрастается и устаревает, поэтому нужен способ снести его, не трогая
  # основное окружение (нижний слой overlayfs остаётся нетронутым по построению).
  vpn-zone-profile-rm-gui = pkgs.writeShellScriptBin "vpn-zone-profile-rm-gui" ''
    set -eu
    profiles="${profilesDir}"
    root="${stateDir}"
    vpnzone=${config.home.profileDirectory}/bin/vpn-zone

    menu=()
    total=0
    for d in "$profiles"/*/; do
      [ -d "$d" ] || continue
      pn=$(${pkgs.coreutils}/bin/basename "$d")
      size=$(${pkgs.coreutils}/bin/du -sh "$d" 2>/dev/null | ${pkgs.coreutils}/bin/cut -f1)
      busy=""
      for f in "$root/.running/$pn"/*; do
        [ -f "$f" ] || continue
        while read -r pid z _; do
          [ -n "''${pid:-}" ] && [ -d "/proc/$pid" ] && { busy="$z"; break; }
        done < "$f"
        [ -n "$busy" ] && break
      done
      if [ -n "$busy" ]; then
        menu+=( "$pn" "$pn — $size, сейчас открыт в сети $busy" )
      else
        menu+=( "$pn" "$pn — $size" )
      fi
      total=$((total + 1))
    done

    if [ $total -eq 0 ]; then
      ${kdialog} --msgbox "Профилей нет.

Профиль создаётся при запуске программы: выбери «➕ Новый профиль…» во втором окне выбора." 2>/dev/null || true
      exit 0
    fi

    [ $total -gt 1 ] && menu+=( "__all__" "⚠ Удалить ВСЕ профили ($total)" )

    choice=$(${kdialog} --title "Удалить профиль" \
      --menu "Какой контейнер данных удалить? Основное окружение не пострадает" \
      "''${menu[@]}" 2>/dev/null) || exit 0
    [ -n "''${choice:-}" ] || exit 0

    if [ "$choice" = "__all__" ]; then
      warn=$(printf 'Удалить ВСЕ профили (%s)?\n\nПропадут накопленные в них настройки, куки и сессии. Твоё основное окружение (~/.config и остальное) не тронется.' "$total")
    else
      warn=$(printf 'Удалить профиль «%s»?\n\nПропадут его настройки, куки и сессии. Основное окружение не тронется.' "$choice")
    fi
    ${kdialog} --title "Точно удалить?" --warningcontinuecancel "$warn" 2>/dev/null || exit 0

    if [ "$choice" = "__all__" ]; then
      for d in "$profiles"/*/; do
        [ -d "$d" ] || continue
        "$vpnzone" profile rm "$(${pkgs.coreutils}/bin/basename "$d")" >/dev/null 2>&1 || true
      done
      ${notify} -a "VPN-зоны" -t 6000 "Профили удалены" "Снесены все $total контейнеров данных."
    else
      if "$vpnzone" profile rm "$choice" >/dev/null 2>&1; then
        ${notify} -a "VPN-зоны" -t 6000 "Профиль удалён" "Контейнер «$choice» снесён."
      else
        ${kdialog} --error "Не удалось удалить профиль «$choice»" 2>/dev/null || true
      fi
    fi
  '';

  # --- ЧАСТЬ 4г: СОЗДАНИЕ КОНТЕЙНЕРА ЯРЛЫКОМ ---
  # Раньше контейнер заводился только по ходу запуска программы («➕ Новый
  # профиль…» в пикере) или командой. Отдельный ярлык нужен, чтобы подготовить
  # окружение заранее — например, завести «работа» и «личное» и дальше просто
  # выбирать их из списка.
  vpn-zone-profile-add-gui = pkgs.writeShellScriptBin "vpn-zone-profile-add-gui" ''
    set -eu
    vpnzone=${config.home.profileDirectory}/bin/vpn-zone
    name=$(${kdialog} --title "Новый контейнер" \
      --inputbox "Название контейнера (буквы, цифры, дефис). Контейнер хранит настройки и сессии отдельно, но видит текущие как исходные, пока сам их не изменит." "" 2>/dev/null) || exit 0
    name=$(printf '%s' "$name" | ${pkgs.gnused}/bin/sed -e 's#[/"'"'"'`\\]#_#g' -e 's/ /_/g' -e 's/^[-.]*//')
    [ -n "$name" ] || exit 0
    if out=$("$vpnzone" profile create "$name" 2>&1); then
      ${notify} -a "VPN-зоны" -t 6000 "Контейнер «$name» создан" \
        "Выбирай его во втором окне при запуске программы."
    else
      ${kdialog} --error "Не удалось создать: $out" 2>/dev/null || true
    fi
  '';

  # --- ЧАСТЬ 4д: НАСТРОЙКИ ЯРЛЫКОМ ---
  # Всё, что раньше жило только в командах: сеть и контейнер по умолчанию, режим
  # ярлыков, замки зон. Меню показывает текущие значения — иначе про настройку
  # просто не вспомнишь, а угадать её состояние неоткуда.
  vpn-zone-settings-gui = pkgs.writeShellScriptBin "vpn-zone-settings-gui" ''
    set -eu
    root="${stateDir}"
    profiles="${profilesDir}"
    cfg="${config.home.homeDirectory}/.config/vpn-zones"
    vpnzone=${config.home.profileDirectory}/bin/vpn-zone
    ${pkgs.coreutils}/bin/mkdir -p "$cfg"

    curnet=$(${pkgs.coreutils}/bin/cat "$cfg/default" 2>/dev/null || echo offline)
    curprof=$(${pkgs.coreutils}/bin/cat "$cfg/default-profile" 2>/dev/null || echo ask)
    curmode=$(${pkgs.coreutils}/bin/cat "$cfg/mode" 2>/dev/null || echo picker)
    curwl=$(${pkgs.coreutils}/bin/cat "$cfg/wayland-sandbox" 2>/dev/null || echo on)

    what=$(${kdialog} --title "Настройки VPN-зон" --menu "Что настроить?" \
      net "Сеть по умолчанию — сейчас: $curnet" \
      prof "Контейнер по умолчанию — сейчас: $curprof" \
      mode "Ярлыки программ — сейчас: $curmode" \
      wl "Доступ к экрану и вводу — сейчас: $curwl" \
      lock "Замки зон (кому запрещено выходить в другие сети)" \
      2>/dev/null) || exit 0

    case "$what" in
      net)
        menu=( offline "Без сети (безопасный выбор для незнакомой программы)" direct "Прямой интернет" )
        for d in "$root"/*/; do
          [ -d "$d" ] || continue
          z=$(${pkgs.coreutils}/bin/basename "$d")
          case "$z" in .*|offline) continue;; esac
          [ -f "$d/config.conf" ] || continue
          menu+=( "$z" "VPN: $z" )
        done
        v=$(${kdialog} --title "Сеть по умолчанию" --default "$curnet" \
          --menu "Что предлагать для программы, которую запускаешь впервые?" "''${menu[@]}" 2>/dev/null) || exit 0
        "$vpnzone" default "$v" >/dev/null && ${notify} -a "VPN-зоны" -t 4000 "Сеть по умолчанию" "$v"
        ;;
      prof)
        menu=( ask "Спрашивать каждый раз" main "Всегда основной (общий с системой)" \
               own "У каждой программы своя постоянная песочница" )
        for d in "$profiles"/*/; do
          [ -d "$d" ] || continue
          pn=$(${pkgs.coreutils}/bin/basename "$d")
          menu+=( "$pn" "Всегда «$pn»" )
        done
        v=$(${kdialog} --title "Контейнер по умолчанию" --default "$curprof" \
          --menu "Спрашивать ли контейнер при каждом запуске?" "''${menu[@]}" 2>/dev/null) || exit 0
        "$vpnzone" default-profile "$v" >/dev/null && ${notify} -a "VPN-зоны" -t 4000 "Контейнер по умолчанию" "$v"
        ;;
      mode)
        v=$(${kdialog} --title "Ярлыки программ" --default "$curmode" --menu "Как вести себя ярлыкам?" \
          picker "Один ярлык, спрашивает сеть при запуске" \
          per-zone "Отдельный ярлык на каждую зону" \
          both "И то, и другое" \
          off "Не трогать ярлыки" 2>/dev/null) || exit 0
        "$vpnzone" mode "$v" >/dev/null && ${notify} -a "VPN-зоны" -t 4000 "Режим ярлыков" "$v"
        ;;
      wl)
        v=$(${kdialog} --title "Доступ к экрану и вводу" --default "$curwl" \
          --menu "Отбирать ли у программ захват экрана, чтение буфера в фоне и эмуляцию ввода? Исключения (скриншотилки, менеджер буфера) — в ~/.config/vpn-zones/wayland-allow" \
          on "Отбирать — программа видит только свои окна" \
          off "Не отбирать — как было до этой настройки" 2>/dev/null) || exit 0
        "$vpnzone" wayland-sandbox "$v" >/dev/null && ${notify} -a "VPN-зоны" -t 4000 "Доступ к экрану" "$v"
        ;;
      lock)
        menu=()
        for d in "$root"/*/; do
          [ -d "$d" ] || continue
          z=$(${pkgs.coreutils}/bin/basename "$d")
          case "$z" in .*) continue;; esac
          if [ -f "$d/no-escape" ]; then
            menu+=( "$z" "$z — ЗАПЕРТА (снять замок)" )
          else
            menu+=( "$z" "$z — открыта (запереть)" )
          fi
        done
        [ ''${#menu[@]} -gt 0 ] || { ${kdialog} --msgbox "Зон нет." 2>/dev/null || true; exit 0; }
        z=$(${kdialog} --title "Замки зон" \
          --menu "Запертая зона не выпускает свои программы в другие сети — это нужно карантинным, а не VPN" \
          "''${menu[@]}" 2>/dev/null) || exit 0
        if [ -f "$root/$z/no-escape" ]; then
          "$vpnzone" unlock "$z" >/dev/null && ${notify} -a "VPN-зоны" -t 4000 "Зона «$z»" "замок снят"
        else
          "$vpnzone" lock "$z" >/dev/null && ${notify} -a "VPN-зоны" -t 4000 "Зона «$z»" "заперта"
        fi
        ;;
    esac
  '';

  # --- ЧАСТЬ 5: графическое добавление зоны ---
  vpn-zone-add-gui = pkgs.writeShellScriptBin "vpn-zone-add-gui" ''
    set -eu
    conf=$(${kdialog} --title "Конфиг VPN" \
      --getopenfilename "$HOME" "*.conf|Конфигурация WireGuard/AmneziaWG (*.conf)" 2>/dev/null) || exit 0
    [ -n "$conf" ] || exit 0

    suggest=$(${pkgs.coreutils}/bin/basename "$conf" .conf | ${pkgs.gnused}/bin/sed 's/[^a-zA-Z0-9_-]/-/g')
    name=$(${kdialog} --title "Имя зоны" \
      --inputbox "Как назвать зону? Это имя попадёт в ярлыки: Chromium ($suggest)" "$suggest" 2>/dev/null) || exit 0
    [ -n "$name" ] || exit 0

    if ! ${vpn-zone}/bin/vpn-zone add "$name" "$conf" 2>&1; then
      ${kdialog} --error "Не удалось создать зону $name" 2>/dev/null || true
      exit 1
    fi

    if ${vpn-zone}/bin/vpn-zone up "$name" >/dev/null 2>&1; then
      ${vpn-zone}/bin/vpn-zone sync >/dev/null 2>&1 || true
      # Даём зоне секунды на рукопожатие и сразу говорим, живой ли конфиг: ради
      # этого ответа зону обычно и создают («какой из моих .conf ещё работает?»).
      ${pkgs.coreutils}/bin/sleep 6
      if ${vpn-zone}/bin/vpn-zone check "$name" >/dev/null 2>&1; then
        ${notify} -a "VPN-зоны" -t 8000 "Зона «$name» готова" \
          "Рукопожатие прошло — конфиг рабочий. Запускай программы: они спросят сеть при старте."
      else
        ${notify} -a "VPN-зоны" -u critical -t 10000 "Зона «$name» поднята, но туннель молчит" \
          "Рукопожатия нет: конфиг устарел или сервер недоступен. Зону можно удалить ярлыком «Удалить VPN-зону»."
      fi
    else
      ${notify} -a "VPN-зоны" -u critical -t 8000 "Зона «$name» не поднялась" \
        "Смотри: journalctl --user -u vpn-zone@$name"
    fi
  '';
in
{
  options.programs.vpn-zones = {
    enable = lib.mkEnableOption "сетевые зоны с VPN, контейнеры данных и песочницы для запуска программ";
  };

  config = lib.mkIf config.programs.vpn-zones.enable {
  home.packages = [
    vpn-zone
    vpn-zone-sync
    vpn-zone-pick
    wl-sandbox
    vpn-fs-sandbox
    # Rust-ядро: vpn-zone-seccomp (генератор фильтра) и vpn-zone-core
    # (подкоманды profile-run и sync, их зовёт vpn-zone). В PATH — не только
    # ради песочницы: тем же бинарём проверяется, что фильтр вообще работает
    # на твоём ядре (`vpn-zone-seccomp selftest`).
    vpn-zone-rust
    vpn-zone-add-gui
    vpn-zone-remove-gui
    vpn-zone-profile-rm-gui
    vpn-zone-profile-add-gui
    vpn-zone-settings-gui
    vpn-zone-forget-gui
    pkgs.passt # userspace-сеть для зон
    pkgs.kdePackages.kdialog # файлпикер в стиле остального десктопа
  ];

  # Шаблонный юнит: одна зона — один экземпляр. Останавливается по обычному
  # systemctl --user stop, переживает выход из графической сессии (зона живёт,
  # пока её не погасить), логи — journalctl --user -u vpn-zone@<имя>.
  systemd.user.services."vpn-zone@" = {
    Unit = {
      Description = "VPN-зона %i (сетевое пространство с туннелем)";
      After = [ "network-online.target" ];
    };
    Service = {
      Type = "simple";
      ExecStart = "${zoneHolder} %i";
      Restart = "no";
      # KillMode=control-group по умолчанию: гасим зону — гаснет и pasta, и всё,
      # что в зоне работало, теряет сеть. Это и есть kill switch.
    };
  };

  # Ярлыки пересобираются: раз в полчаса, при входе в сессию и при изменении
  # каталогов с .desktop (после nixos-rebuild там появляются новые программы).
  systemd.user.services.vpn-zone-desktop-sync = {
    Unit.Description = "Пересборка ярлыков VPN-зон";
    Service = {
      Type = "oneshot";
      ExecStart = "${vpn-zone-sync}/bin/vpn-zone-sync";
    };
  };

  systemd.user.timers.vpn-zone-desktop-sync = {
    Unit.Description = "Регулярная пересборка ярлыков VPN-зон";
    Timer = {
      OnStartupSec = "2m";
      OnUnitActiveSec = "30m";
      Persistent = true;
    };
    Install.WantedBy = [ "timers.target" ];
  };

  # Пересборка ярлыков сразу после активации. Без этого шага порядок был
  # случайным: таймер или path-юнит могли отработать ДО подмены профиля, ярлыки
  # оставались в старом формате, а пикер приезжал новый — и запуск программ
  # ломался до следующего срабатывания таймера.
  home.activation.vpnZoneSync = lib.hm.dag.entryAfter [ "linkGeneration" ] ''
    $DRY_RUN_CMD ${vpn-zone-sync}/bin/vpn-zone-sync || true
  '';

  systemd.user.paths.vpn-zone-desktop-sync = {
    Unit.Description = "Следить за появлением новых .desktop";
    Path = {
      PathChanged = [
        "${config.home.homeDirectory}/.local/share/applications"
        "/etc/profiles/per-user/${config.home.username}/share/applications"
        "/run/current-system/sw/share/applications"
      ];
      Unit = "vpn-zone-desktop-sync.service";
    };
    Install.WantedBy = [ "paths.target" ];
  };

  xdg.desktopEntries."vpn-zone-remove" = {
    name = "Удалить VPN-зону";
    comment = "Остановить и удалить зону вместе с её конфигом";
    exec = "${vpn-zone-remove-gui}/bin/vpn-zone-remove-gui";
    icon = "network-vpn";
    terminal = false;
    type = "Application";
    categories = [ "Network" ];
  };

  # Сброс закреплений. Имя файла начинается с vpn-zone- — значит генератор
  # ярлыков его не тронет и сам себя не перехватит.
  xdg.desktopEntries."vpn-zone-profile-add" = {
    name = "Создать контейнер";
    comment = "Завести отдельное хранилище настроек и сессий заранее, до запуска программ";
    exec = "${vpn-zone-profile-add-gui}/bin/vpn-zone-profile-add-gui";
    icon = "folder-new";
    terminal = false;
    type = "Application";
    categories = [ "Network" ];
  };

  xdg.desktopEntries."vpn-zone-settings" = {
    name = "Настройки VPN-зон";
    comment = "Сеть и контейнер по умолчанию, поведение ярлыков, замки зон";
    exec = "${vpn-zone-settings-gui}/bin/vpn-zone-settings-gui";
    icon = "configure";
    terminal = false;
    type = "Application";
    categories = [ "Network" ];
  };

  xdg.desktopEntries."vpn-zone-profile-rm" = {
    name = "Удалить профиль (контейнер)";
    comment = "Снести накопленный слой данных — у одного профиля или у всех сразу";
    exec = "${vpn-zone-profile-rm-gui}/bin/vpn-zone-profile-rm-gui";
    icon = "edit-delete";
    terminal = false;
    type = "Application";
    categories = [ "Network" ];
  };

  xdg.desktopEntries."vpn-zone-forget" = {
    name = "Сбросить сети программ";
    comment = "Забыть, в какой сети запускать программу — у одной или у всех сразу";
    exec = "${vpn-zone-forget-gui}/bin/vpn-zone-forget-gui";
    icon = "edit-clear-history";
    terminal = false;
    type = "Application";
    categories = [ "Network" ];
  };

  # Тот самый пункт в лаунчере (Super+Space → «VPN»).
  xdg.desktopEntries."vpn-zone-add" = {
    name = "Добавить VPN-зону (AmneziaWG)";
    comment = "Выбрать .conf и создать сетевую зону; ко всем приложениям появятся ярлыки «(имя зоны)»";
    exec = "${vpn-zone-add-gui}/bin/vpn-zone-add-gui";
    icon = "network-vpn";
    terminal = false;
    type = "Application";
    categories = [ "Network" ];
  };
  };
}
