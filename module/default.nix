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
# УСТРОЙСТВО (ключевой момент — двойной маппинг uid). Всё это делает
# `vpn-zone-core zone-holder <имя>` (rust/src/zone.rs), его запускает юнит:
#   user namespace: 0→<subuid> и <uid>→<uid>, внутри setuid 0
#     ├── net+mount namespace ─ АПЛИНК: pasta, выход наружу и UDP-сокет туннеля;
#     │                         здесь awg0 создаётся и сразу переезжает вниз
#     ├── pasta --netns <аплинк> ─ выход в интернет
#     └── net+mount namespace ─ ЗОНА ПРИЛОЖЕНИЙ: только lo и awg0, маршруты в
#                               туннель, свой resolv.conf — сюда входит nsenter
# ДВА namespace, а не один, и это главное свойство безопасности: у программ нет
# ни одного интерфейса, кроме туннеля, поэтому утечка невозможна не потому, что
# запрещена правилом, а потому, что пути не существует — ни в LAN, ни мимо VPN,
# ни для какого семейства протоколов. Держится на свойстве WireGuard: UDP-сокет
# остаётся в том namespace, где интерфейс был создан. Подробности —
# docs/LEAK-MODEL.md.
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

  # --- ЧАСТЬ 0: RUST-ЯДРО ---
  # Отсюда идёт переезд ядра на Rust (ROADMAP M1/M2). Первым переехало то, чего
  # в bash нет в принципе: BPF-фильтр системных вызовов для песочницы —
  # программу для ядра умеет собрать только код (libseccomp). Следом переехали
  # оба бывших python-скрипта: наложение слоёв профиля при запуске программы и
  # генератор .desktop-ярлыков. Затем — ограничитель доступа к композитору,
  # он же бывшая программа на C (module/wl-sandbox.c): создаёт помеченный
  # wayland-сокет, после чего композитор перестаёт выдавать клиенту протоколы
  # слежки. Ни Python, ни C в проекте больше нет.
  #
  # Затем переехал ЖИЗНЕННЫЙ ЦИКЛ ЗОНЫ — то, что раньше было скриптами
  # zoneHolder и zoneInit прямо в этом файле: user namespace с двойным
  # маппингом, net+mount namespace, pasta, туннель, DNS и зеркало состояния
  # (`vpn-zone-core zone-holder`, rust/src/zone.rs). Заодно конфиги теперь
  # разбирает парсер крейта с тестами на все грабли docs/GOTCHAS.md §4, а не
  # конвейер sed+grep.
  #
  # Последней переехала ПЕСОЧНИЦА ФАЙЛОВОЙ СИСТЕМЫ — двухсотстрочный
  # writeShellScriptBin vpn-fs-sandbox из этого файла: bwrap, разрешения,
  # /.flatpak-info, фильтр сессионной шины и свой X-сервер
  # (`vpn-zone-core fs-sandbox`, rust/src/fs_sandbox.rs). Seccomp-фильтр она
  # теперь собирает В СВОЁМ ПРОЦЕССЕ (крейт зовётся как библиотека), а не
  # запускает vpn-zone-seccomp сабпроцессом.
  #
  # Последним переехал сам CLI `vpn-zone` — семьсот строк bash из части 3 этого
  # файла (rust/src/cli.rs + launch.rs + registry.rs). На bash остались пикер и
  # GUI-обвязка, и они зовут CLI по прежнему пути профиля.
  #
  # Три бинаря: vpn-zone-seccomp (фильтр отдельной командой — он же selftest),
  # vpn-zone-core (подкоманды zone-holder, profile-run, sync, wl-sandbox и
  # fs-sandbox) и vpn-zone (сам CLI). ПОСЛЕДНИЙ ИМЕНЕМ СТАЛКИВАЕТСЯ с обёрткой
  # из home.packages, поэтому крейт целиком туда не кладётся — в профиль уходит
  # symlink-набор vpn-zone-helpers (см. часть 3).
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
    #
    # А вот libwayland здесь НЕТ, и это осознанный выбор: у wayland-backend
    # фича client_system по умолчанию выключена, то есть wayland-client говорит
    # по проводному протоколу сам, на Rust. Ни линковки, ни dlopen — значит
    # нечему разъехаться с версией композитора и нечего добавлять в buildInputs.
    # Включит кто-нибудь client_system в rust/Cargo.toml — сюда придётся
    # дописать pkgs.wayland.
    nativeBuildInputs = [ pkgs.pkg-config ];
    buildInputs = [ pkgs.libseccomp ];
    # Тесты гоняет CI (job rust). Здесь они выключены сознательно: selftest
    # грузит seccomp-фильтр в собственный процесс, а что разрешает песочница
    # сборки nix — зависит от демона; ломать этим пересборку системы нельзя.
    doCheck = false;
    meta.mainProgram = "vpn-zone-seccomp";
  };

  # --- ЧАСТЬ 0б: ПЕСОЧНИЦА ФАЙЛОВОЙ СИСТЕМЫ — В RUST ---
  # Здесь был writeShellScriptBin vpn-fs-sandbox на две сотни строк. Он целиком
  # переехал в крейт — `vpn-zone-core fs-sandbox`, модуль rust/src/fs_sandbox.rs,
  # где и живёт теперь вся прежняя россыпь комментариев-граблей (порядок
  # аргументов bwrap, узлы NVIDIA, mimeapps.list, задержка X-сервера, отказ от
  # host-X11). Поведение прежнее; три отличия записаны в CHANGELOG.md:
  #   • seccomp-фильтр собирается В ЭТОМ ЖЕ ПРОЦЕССЕ (crate::seccomp как
  #     библиотека) и уходит в bwrap унаследованным дескриптором, вместо
  #     запуска vpn-zone-seccomp сабпроцессом и редиректа `exec 34< файл`;
  #   • не поднявшийся xdg-dbus-proxy больше не роняет запуск: bash биндил его
  #     сокет безусловно, bwrap падал на «Can't find source path», и программа
  #     не открывалась вовсе — вместо мягкой деградации получался отказ;
  #   • прокси гасится и когда сигнал приходит нам: в bash trap жил в сабшелле,
  #     который TERM убивал отдельно, оставляя прокси висеть.
  #
  # Коротко о том, зачем этот слой (подробности — в шапке rust/src/fs_sandbox.rs
  # и в docs/GOTCHAS.md §6, §8, §9). Третий слой поверх сети (зона) и данных
  # (контейнер): программа теряет доступ к $HOME целиком, вместо него tmpfs, а
  # наружу торчит только разрешённое. Всё остальное она просит через ПОРТАЛЫ —
  # и переключает её на них подложенный /.flatpak-info, по которому GTK, Qt,
  # Chromium и Electron решают, что изолированы. Полной заменой flatpak это не
  # является: программа берётся из nixpkgs и видит /nix/store, так что
  # «подменить библиотеку» песочница не мешает — она мешает читать ТВОИ файлы.
  #
  # Пути инструментов песочница получает флагами, как и держатель зоны: часть
  # кода исполняется внутри namespace, где PATH может быть каким угодно. Флаги
  # ей передаёт CLI, а сами пути лежат в манифесте ниже (bwrap, dbus-proxy,
  # kdialog, xwayland) — оттуда же их берёт смоук-тест, чтобы проверять ровно
  # то, что поедет пользователю (tests/integration/smoke.sh).

  # --- ЧАСТЬ 1-2: ЖИЗНЕННЫЙ ЦИКЛ ЗОНЫ — В RUST ---
  # Здесь были два shell-скрипта: zoneHolder (создавал user namespace двойным
  # маппингом и запускал pasta) и zoneInit (настраивал внутри туннель, маршруты
  # и DNS). Оба переехали в крейт целиком — `vpn-zone-core zone-holder <имя>`,
  # модуль rust/src/zone.rs. Держится всё на том же непривилегированном userns,
  # но namespace теперь ДВА: аплинк (там pasta и сокет туннеля) и зона
  # приложений, где нет ничего, кроме lo и awg0 — см. шапку файла и
  # docs/LEAK-MODEL.md.
  #
  # Что дал переезд:
  #   • конфиг разбирает оттестированный парсер (rust/src/config.rs) вместо
  #     конвейера sed+grep — CRLF, пустые I1…I5, три формы Endpoint и оба
  #     семейства адресов закрыты юнит-тестами (docs/GOTCHAS.md §4);
  #   • ни одной подстановки в shell: ip/awg/wg/pasta исполняются exec'ом
  #     напрямую, аргументами-массивами;
  #   • маппинг uid делается своим fork+newuidmap, а не через unshare(1).
  #
  # Контракт каталога зоны не изменился: zone.pid — это namespace ПРИЛОЖЕНИЙ
  # (цель nsenter в run/status), ready/status/resolv.conf — прежние. Добавился
  # uplink.pid; gc про него знать не обязан — он находит осиротевшую pasta по
  # номеру netns из её командной строки, а это теперь номер аплинка.
  # Пути инструментов подставляет Nix флагами в ExecStart юнита vpn-zone@ (см.
  # ниже): часть кода работает внутри namespace, где PATH может быть каким
  # угодно.

  # --- ЧАСТЬ 3: пользовательский CLI ---
  # Здесь лежали семьсот строк bash: add/up/down/list/status/check/run/gc,
  # реестр запусков с flock, разбор флагов запуска и вся остальная россыпь
  # команд. Всё переехало в крейт — `vpn-zone` (rust/src/cli.rs), запуск со
  # всеми граблями (rust/src/launch.rs) и реестр (rust/src/registry.rs).
  # Пользовательские тексты и коды выхода сохранены дословно: их читает человек
  # в терминале, а `vpn-zone check` ещё и грепают. На bash остались пикер и
  # GUI-обвязка.
  #
  # ПУТИ ИНСТРУМЕНТОВ — МАНИФЕСТОМ. Скомпилированный бинарь не умеет того, на
  # чём стоял скрипт: подстановки строк Nix'ом. А абсолютные пути обязательны —
  # часть кода работает внутри namespace, где PATH может быть каким угодно
  # (docs/GOTCHAS.md §12). Поэтому Nix кладёт их в маленький JSON в store, а
  # обёртка ниже показывает на него ЕДИНСТВЕННОЙ переменной окружения. Ключи
  # перечислены в rust/src/tools.rs; отсутствие любого — внятная ошибка при
  # старте, а не сюрприз посреди запуска программы.
  vpn-zone-tools = pkgs.writeText "vpn-zone-tools.json" (
    builtins.toJSON {
      home = config.home.homeDirectory;
      state = stateDir;
      profiles = profilesDir;
      sandboxes = "${config.home.homeDirectory}/.local/state/vpn-sandboxes";
      config = "${config.home.homeDirectory}/.config/vpn-zones";
      # ПРОФИЛЬНЫЕ пути, а не store: так разрывается зависимость по кругу
      # (vpn-zone зовёт sync, sync подставляет vpn-zone в ярлыки) и ярлыки не
      # протухают после каждой пересборки пакета (docs/GOTCHAS.md §10).
      runner = "${config.home.profileDirectory}/bin/vpn-zone";
      picker = "${config.home.profileDirectory}/bin/vpn-zone-pick";
      # А ядро — наоборот, store-путём: оно версионируется вместе с CLI, и
      # разъезжаться им нельзя.
      core = "${vpn-zone-rust}/bin/vpn-zone-core";
      systemctl = "${pkgs.systemd}/bin/systemctl";
      systemd-run = "${pkgs.systemd}/bin/systemd-run";
      nsenter = "${pkgs.util-linux}/bin/nsenter";
      unshare = "${pkgs.util-linux}/bin/unshare";
      ip = iproute;
      inherit kdialog;
      # Эти три CLI не запускает сам — он передаёт их флагами песочнице ФС,
      # ровно как юнит передаёт держателю зоны --ip/--pasta.
      bwrap = "${pkgs.bubblewrap}/bin/bwrap";
      dbus-proxy = "${pkgs.xdg-dbus-proxy}/bin/xdg-dbus-proxy";
      xwayland = "${pkgs.xwayland-satellite}/bin/xwayland-satellite";
      # awg/wg/pasta здесь намеренно НЕТ: их зовёт только держатель зоны, и
      # получает он их флагами ExecStart своего юнита. Дублировать пути в двух
      # местах — значит однажды поменять их в одном.
    }
  );

  # Обёртка в две строки: назначить манифест и стать бинарём. Имя vpn-zone
  # занимает именно она — по нему CLI зовут пикер, GUI и ярлыки. Такой же
  # bin/vpn-zone есть и в крейте, поэтому крейт целиком в профиль не кладётся
  # (см. vpn-zone-helpers ниже), иначе два одинаковых имени столкнулись бы.
  vpn-zone = pkgs.writeShellScriptBin "vpn-zone" ''
    export VPN_ZONE_TOOLS=${vpn-zone-tools}
    exec ${vpn-zone-rust}/bin/vpn-zone "$@"
  '';

  # Помощники крейта в PATH: ядро (его зовёт юнит vpn-zone@ и сам CLI) и
  # генератор seccomp-фильтра — тем же бинарём проверяется, что фильтр вообще
  # работает на твоём ядре (`vpn-zone-seccomp selftest`). Симлинки, а не копии:
  # ссылка на store-путь тянет за собой сам крейт.
  vpn-zone-helpers = pkgs.runCommand "vpn-zone-helpers" { } ''
    mkdir -p $out/bin
    ln -s ${vpn-zone-rust}/bin/vpn-zone-core $out/bin/vpn-zone-core
    ln -s ${vpn-zone-rust}/bin/vpn-zone-seccomp $out/bin/vpn-zone-seccomp
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
  # VPN_ZONE_PROFILE — служебная: ею пикер передаёт САМ СЕБЕ выбранный
  # контейнер между двумя проходами («⚙ Сменить контейнер» → снова вопрос о
  # сети). Руками её ставить незачем, и она снимается сразу после чтения.
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

    # Контейнер, выбранный только что в «⚙ Сменить контейнер» и донесённый
    # сюда re-exec'ом (см. ниже). Читаем СРАЗУ и убираем из окружения: иначе
    # переменная уехала бы в саму программу, и ссылка, открытая из неё,
    # унаследовала бы чужой контейнер.
    reprofile=''${VPN_ZONE_PROFILE:-}
    unset VPN_ZONE_PROFILE

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
      # Без графики спрашивать негде: kdialog тут просто падает, а «|| exit 0»
      # ниже принимал это за отмену — запуск из терминала или из юнита тихо
      # заканчивался ничем. Берём прошлый выбор и не мешаем программе
      # запуститься (так же поступают предупреждение о конфликте сетей и
      # диалог прав песочницы — см. vpn-zone run и rust/src/fs_sandbox.rs).
      if [ -z "''${WAYLAND_DISPLAY:-}''${DISPLAY:-}" ]; then
        case "''${lastprofile:-}" in
          ""|__main__) ;;
          __fs__) fssand=1 ;;
          sb:*) sandbox=''${lastprofile#sb:}; fssand=1 ;;
          *) [ -d "${profilesDir}/$lastprofile" ] && profile=$lastprofile ;;
        esac
        return 0
      fi
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
          # «|| true» и проверка каталога — не перестраховка: под set -e
          # неудача создания (кончилось место, права) убивала бы пикер прямо
          # тут, молча, уже ПОСЛЕ всех диалогов — человек отвечал на вопросы, а
          # программа не запускалась. Не вышло — идём в основной, но идём.
          "$vpnzone" sandbox create "$sname" >/dev/null 2>&1 || true
          [ -d "${config.home.homeDirectory}/.local/state/vpn-sandboxes/$sname" ] \
            || { profile=""; return 0; }
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
        # Та же грабля, что и у песочницы выше: без «|| true» set -e убивал бы
        # пикер после всех диалогов, а с несуществующим профилем `vpn-zone run`
        # честно отказался бы запускаться. Не создалось — запускаем в основном.
        "$vpnzone" profile create "$pname" >/dev/null 2>&1 || true
        [ -d "${profilesDir}/$pname" ] || { profile=""; return 0; }
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
    # sb:<имя> — ПЕСОЧНИЦА, а не профиль: её дом лежит в vpn-sandboxes и
    # заводится сам при первом запуске. Раньше она проверялась как профиль,
    # каталога с именем «sb:имя» среди профилей, разумеется, не находилось — и
    # закрепление стиралось на первом же следующем клике. То есть пункты
    # «🔒 Своя песочница — всегда» и «Песочница «X» — всегда» не работали
    # вовсе: выбор запоминался ровно до следующего запуска.
    case "''${pinnedprof:-}" in
      ""|__main__|__fs__|sb:*) ;;
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
      # Закреплённый контейнер важнее прошлого выбора: без этого пункт обещал
      # «сейчас: основной», а программа открывалась в закреплённом — состояние
      # в меню расходилось с тем, что происходит на самом деле.
      curp=''${pinnedprof:-''${lastprofile:-}}
      case "$curp" in
        ""|__main__) curplabel="основной" ;;
        __fs__) curplabel="разовая песочница" ;;
        sb:app-*) curplabel="своя песочница" ;;
        sb:*) curplabel="песочница ''${curp#sb:}" ;;
        *) curplabel=$curp ;;
      esac
      menu+=( __chooseprofile__ "⚙ Сменить контейнер (сейчас: $curplabel)…" )
      [ -n "''${pinned:-}" ] && menu+=( unpin "↺ Спрашивать сеть снова (закреплено: $pinned)" )

      if [ -z "''${WAYLAND_DISPLAY:-}''${DISPLAY:-}" ]; then
        # Без графики диалог показать негде: kdialog падает сразу, а «|| exit 0»
        # принимал это за отмену — клик (или запуск из терминала) тихо
        # заканчивался ничем, без единого слова. Берём то, что было бы выделено
        # в меню: прошлый выбор, иначе общий дефолт.
        choice=$default
        echo "vpn-zone-pick: спросить негде (нет графики) — беру «$choice»" >&2
      else
        choice=$(${kdialog} --title "Куда пустить «$label»?" \
          --default "$default" \
          --menu "Выбери сеть для запуска" "''${menu[@]}" 2>/dev/null) || exit 0
        [ -n "''${choice:-}" ] || exit 0
      fi

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
        # Выбор доносим до второго прохода ЕЩЁ И ПЕРЕМЕННОЙ, не только файлом.
        # Одноразовый контейнер в .lastprofile не пишется (иначе он стал бы
        # постоянным) — и после re-exec терялся начисто: человек выбирал
        # «🗑 Новый временный», а программа молча открывалась в прежнем,
        # постоянном контейнере. Для песочницы это прямая потеря изоляции, а не
        # мелочь. Пустой выбор («Основной») передаём как __main__: пустую строку
        # не отличить от «не задано».
        exec env VPN_ZONE_ASK=1 VPN_ZONE_PROFILE="''${sel:-__main__}" \
          "$0" --id "$key" -- "''${cmd[@]}"
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
    elif [ -n "''${reprofile:-}" ]; then
      # Контейнер только что выбран в «⚙ Сменить контейнер» — он сильнее и
      # закрепления, и .lastprofile: это ответ на вопрос, заданный секунду
      # назад.
      case "$reprofile" in
        __main__) profile="" ;;
        __fs__) profile=""; fssand=1 ;;
        sb:*) profile=""; fssand=1; sandbox=''${reprofile#sb:} ;;
        *) profile=$reprofile ;;
      esac
    elif [ -n "''${pinnedprof:-}" ]; then
      # Проверки на VPN_ZONE_ASK тут больше нет, и это исправление: свежий
      # выбор приходит переменной выше, а без неё ASK=1 (пункт «↺ Спрашивать
      # сеть снова») ронял закреплённый контейнер в «основной» — .lastprofile у
      # закрепивших контейнер обычно пуст, и программа открывалась не там.
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
      # В уведомлении — метка, а не ключ: ключ это id ярлыка
      # (com.ayugram.desktop), по нему не догадаешься, о какой программе речь.
      # Ровно ради этого метки и заводились, а тут они не использовались.
      nm=$(${pkgs.coreutils}/bin/cat "$root/.labels/$choice" 2>/dev/null || echo "$choice")
      ${config.home.profileDirectory}/bin/vpn-zone forget "$choice" >/dev/null
      ${notify} -a "VPN-зоны" -t 5000 "Сброшено" "Для «$nm» сеть снова будет спрашиваться."
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
    # Помощники Rust-ядра: vpn-zone-core (подкоманды zone-holder, profile-run,
    # sync, wl-sandbox и fs-sandbox — их зовут юнит и сам CLI) и
    # vpn-zone-seccomp (генератор фильтра, он же selftest). Сам CLI приходит
    # обёрткой vpn-zone выше — крейт целиком сюда класть нельзя, в нём тоже есть
    # bin/vpn-zone.
    vpn-zone-helpers
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
      # Держатель зоны — подкоманда rust-ядра (rust/src/zone.rs). Пути
      # инструментов подставляются здесь, а не ищутся в PATH: часть кода
      # исполняется внутри namespace, где PATH может быть каким угодно.
      # Исключение — newuidmap/newgidmap: их держатель ищет ИМЕННО в PATH, как
      # это делал unshare(1), потому что setuid-обёртки лежат в /run/wrappers/bin
      # и в store их нет.
      ExecStart =
        "${vpn-zone-rust}/bin/vpn-zone-core zone-holder"
        + " --ip ${iproute} --awg ${awg} --wg ${wg} --pasta ${pasta} %i";
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
