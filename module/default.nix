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
  # Второй эшелон герметичности (docs/LEAK-MODEL.md): фаерволл в обоих
  # namespace зоны. Зовёт его только держатель зоны, поэтому путь идёт флагом
  # ExecStart, как ip/awg/wg/pasta, а не манифестом.
  nft = "${pkgs.nftables}/bin/nft";
  # Второй тип зоны — [OpenConnect] (Cisco AnyConnect/ocserv, а через
  # --protocol ещё GlobalProtect и Pulse). Клиент работает В АПЛИНКЕ, его tun
  # переезжает в зону приложений; путь идёт флагом ExecStart, как ip/awg/wg/
  # pasta/nft, потому что зовёт его только держатель зоны.
  #
  # Штатный vpnc-script сюда НЕ ставится намеренно: --script держателя — это
  # наш же vpn-zone-core oc-script, и подменить его конфигом зоны нельзя
  # (белый список Args=, rust/src/openconnect.rs). Обычный vpnc-script
  # настраивал бы сеть ХОСТА.
  openconnect = "${pkgs.openconnect}/bin/openconnect";
  notify = "${pkgs.libnotify}/bin/notify-send";
  kdialog = "${pkgs.kdePackages.kdialog}/bin/kdialog";

  # --- ЧАСТЬ 0: RUST-ЯДРО ---
  # Здесь ЗАКОНЧИЛСЯ переезд ядра на Rust (ROADMAP M1). Первым переехало то,
  # чего в bash нет в принципе: BPF-фильтр системных вызовов для песочницы —
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
  # Потом переехала ПЕСОЧНИЦА ФАЙЛОВОЙ СИСТЕМЫ — двухсотстрочный
  # writeShellScriptBin vpn-fs-sandbox из этого файла: bwrap, разрешения,
  # /.flatpak-info, фильтр сессионной шины и свой X-сервер
  # (`vpn-zone-core fs-sandbox`, rust/src/fs_sandbox.rs). Seccomp-фильтр она
  # теперь собирает В СВОЁМ ПРОЦЕССЕ (крейт зовётся как библиотека), а не
  # запускает vpn-zone-seccomp сабпроцессом.
  #
  # Затем переехал сам CLI `vpn-zone` — семьсот строк bash из части 3 этого
  # файла (rust/src/cli.rs + launch.rs + registry.rs).
  #
  # И последними — ПИКЕР СЕТИ и ВСЯ GUI-ОБВЯЗКА: четыреста строк vpn-zone-pick
  # и шесть writeShellScriptBin с диалогами (rust/src/picker.rs, rust/src/gui.rs
  # и общий rust/src/dialog.rs). Логики на shell в проекте не осталось нигде:
  # в этом файле от неё три двухстрочные обёртки, которые назначают
  # VPN_ZONE_TOOLS и делают exec.
  #
  # Пять бинарей: vpn-zone-seccomp (фильтр отдельной командой — он же selftest),
  # vpn-zone-core (подкоманды zone-holder, profile-run, sync, wl-sandbox и
  # fs-sandbox), vpn-zone (сам CLI), vpn-zone-pick (пикер) и vpn-zone-gui
  # (шесть ярлыков одной подкомандой каждый). ДВА ПЕРВЫХ ИМЕНЕМ СТАЛКИВАЮТСЯ с
  # обёртками из home.packages, поэтому крейт целиком туда не кладётся — в
  # профиль уходит symlink-набор vpn-zone-helpers (см. часть 3).
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
  # в терминале, а `vpn-zone check` ещё и грепают.
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
      # Уведомления шлёт только vpn-zone-gui: у CLI то же самое печатается в
      # stdout, а у пикера уведомлению взяться неоткуда — он становится
      # программой.
      notify-send = notify;
      # Эти три CLI не запускает сам — он передаёт их флагами песочнице ФС,
      # ровно как юнит передаёт держателю зоны --ip/--pasta.
      bwrap = "${pkgs.bubblewrap}/bin/bwrap";
      dbus-proxy = "${pkgs.xdg-dbus-proxy}/bin/xdg-dbus-proxy";
      xwayland = "${pkgs.xwayland-satellite}/bin/xwayland-satellite";
      # awg/wg/pasta/nft/openconnect здесь намеренно НЕТ: их зовёт только
      # держатель зоны, и получает он их флагами ExecStart своего юнита.
      # Дублировать пути в двух местах — значит однажды поменять их в одном.
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

  # Tab-дополнение для zsh и bash — тонкие обёртки над скрытой подкомандой
  # `vpn-zone _complete` (rust/src/completion.rs): правила и знание зон,
  # профилей и песочниц живут в крейте рядом с самими командами и покрыты
  # тестами, оболочка только спрашивает и подставляет. Протокол: слова
  # командной строки + 1-based позиция курсора, кандидаты по одному на строку;
  # специальный ответ __files__ — «дополняй файлами сам». NixOS кладёт
  # site-functions профилей в fpath через NIX_PROFILES (/etc/zshrc), bash
  # подхватывает completions профиля пакетом bash-completion.
  vpn-zone-completions =
    let
      zshScript = pkgs.writeText "vpn-zone.zsh-completion" ''
        #compdef vpn-zone
        local -a candidates
        candidates=("''${(@f)$(vpn-zone _complete -- "''${(@)words}" "$CURRENT" 2>/dev/null)}")
        if [[ "''${candidates[1]-}" == __files__ ]]; then
          _files
          return
        fi
        [[ -n "''${candidates[1]-}" ]] && compadd -- "''${candidates[@]}"
      '';
      bashScript = pkgs.writeText "vpn-zone.bash-completion" ''
        _vpn_zone() {
          local -a reply
          mapfile -t reply < <(vpn-zone _complete -- "''${COMP_WORDS[@]}" "$((COMP_CWORD + 1))" 2>/dev/null)
          if [[ "''${reply[0]-}" == __files__ ]]; then
            compopt -o default
            COMPREPLY=()
            return
          fi
          COMPREPLY=("''${reply[@]}")
        }
        complete -F _vpn_zone vpn-zone
      '';
    in
    pkgs.runCommand "vpn-zone-completions" { } ''
      install -Dm444 ${zshScript} $out/share/zsh/site-functions/_vpn-zone
      install -Dm444 ${bashScript} $out/share/bash-completion/completions/vpn-zone
    '';

  # --- ЧАСТЬ 3б: ПИКЕР СЕТИ ---
  # Спрашивает при запуске, куда пустить программу. Вызывается из перехваченных
  # ярлыков (режим picker).
  #
  # Здесь лежали четыреста строк bash: три уровня памяти, два меню kdialog,
  # закрепления по двум независимым осям и re-exec самого себя для второго
  # прохода. Всё переехало в крейт целиком (`vpn-zone-pick`,
  # rust/src/picker.rs), причём решение «какая сеть и какой контейнер» стало
  # ЧИСТОЙ ФУНКЦИЕЙ от снимка состояния — у каждой ветки теперь есть тест, а не
  # только история багфикса. Тексты диалогов, имена файлов памяти и порядок
  # пунктов меню сохранены дословно.
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
  # Сеть и контейнер закрепляются ПОРОЗНЬ (.pinned и .pinnedprofile): это
  # независимые оси, и диалог показывается только для незакреплённой.
  # Принудительно вызвать диалог при закреплённой программе: VPN_ZONE_ASK=1.
  # VPN_ZONE_PROFILE — служебная: ею пикер передаёт САМ СЕБЕ выбранный
  # контейнер между двумя проходами («⚙ Сменить контейнер» → снова вопрос о
  # сети). Руками её ставить незачем, и она снимается сразу после чтения.
  #
  # Обёртка двухстрочная, как у vpn-zone, и по той же причине: имя
  # vpn-zone-pick В ПРОФИЛЕ занимает именно она, потому что этот путь попадает в
  # Exec сгенерированных ярлыков и не должен протухать при каждой пересборке
  # пакета (docs/GOTCHAS.md §10).
  vpn-zone-pick = pkgs.writeShellScriptBin "vpn-zone-pick" ''
    export VPN_ZONE_TOOLS=${vpn-zone-tools}
    exec ${vpn-zone-rust}/bin/vpn-zone-pick "$@"
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

  # --- ЧАСТЬ 4б: ГРАФИЧЕСКИЕ ЯРЛЫКИ ---
  # Здесь лежали шесть writeShellScriptBin — добавить зону, удалить зону,
  # завести контейнер, удалить контейнер, настройки и сброс закреплений. Все
  # шесть были kdialog поверх CLI, и все шесть переехали в крейт одной
  # подкомандой каждый (`vpn-zone-gui <команда>`, rust/src/gui.rs). Тексты
  # диалогов и уведомлений сохранены дословно — включая те места, где bash
  # передавал kdialog литеральные «\n» (в Nix-строке '' … '' обратный слэш
  # ничего не экранирует, и эти два символа так и доезжали до диалога).
  #
  # Обёртки у этого бинаря нет, и она не нужна: ярлыки ниже пишет сам
  # home-manager и пересобирает их на каждом switch, так что store-путь в них не
  # протухает. (У Exec, который генерирует НАШ sync, путь наоборот профильный —
  # там между пересборками никто ярлыки не переписывает, docs/GOTCHAS.md §10.)
  # Манифест ярлык несёт сам, через env(1) абсолютным путём:
  #   Exec=env VPN_ZONE_TOOLS=… …/vpn-zone-gui add
  guiExec =
    verb:
    "${pkgs.coreutils}/bin/env VPN_ZONE_TOOLS=${vpn-zone-tools} ${vpn-zone-rust}/bin/vpn-zone-gui ${verb}";
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
    # vpn-zone-seccomp (генератор фильтра, он же selftest). Сам CLI и пикер
    # приходят обёртками выше — крейт целиком сюда класть нельзя, в нём есть и
    # bin/vpn-zone, и bin/vpn-zone-pick. Ярлычного бинаря vpn-zone-gui здесь
    # нет намеренно: его зовут только .desktop-записи,
    # своим store-путём и со своим VPN_ZONE_TOOLS.
    vpn-zone-helpers
    vpn-zone-completions # Tab-дополнение zsh/bash (см. определение выше)
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
      #
      # --nft — второй эшелон (docs/LEAK-MODEL.md): в app-ns выход только через
      # туннель, в uplink-ns наружу только пакеты самого туннеля до endpoint.
      # Не поднявшийся фаерволл зону НЕ роняет: это страховка поверх топологии,
      # и держатель громко пишет об этом в журнал.
      #
      # --openconnect нужен только зонам с секцией [OpenConnect]; зона на
      # WireGuard/AmneziaWG на этот путь ни разу не смотрит.
      ExecStart =
        "${vpn-zone-rust}/bin/vpn-zone-core zone-holder"
        + " --ip ${iproute} --awg ${awg} --wg ${wg} --pasta ${pasta} --nft ${nft}"
        + " --openconnect ${openconnect} %i";
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
    exec = guiExec "remove";
    icon = "network-vpn";
    terminal = false;
    type = "Application";
    categories = [ "Network" ];
  };

  # Имена всех наших ярлыков начинаются с vpn-zone- — значит генератор ярлыков
  # их не берёт на вход и сам себя не перехватывает (docs/GOTCHAS.md §10).
  xdg.desktopEntries."vpn-zone-profile-add" = {
    name = "Создать контейнер";
    comment = "Завести отдельное хранилище настроек и сессий заранее, до запуска программ";
    exec = guiExec "profile-add";
    icon = "folder-new";
    terminal = false;
    type = "Application";
    categories = [ "Network" ];
  };

  xdg.desktopEntries."vpn-zone-settings" = {
    name = "Настройки VPN-зон";
    comment = "Сеть и контейнер по умолчанию, поведение ярлыков, замки зон";
    exec = guiExec "settings";
    icon = "configure";
    terminal = false;
    type = "Application";
    categories = [ "Network" ];
  };

  xdg.desktopEntries."vpn-zone-profile-rm" = {
    name = "Удалить профиль (контейнер)";
    comment = "Снести накопленный слой данных — у одного профиля или у всех сразу";
    exec = guiExec "profile-rm";
    icon = "edit-delete";
    terminal = false;
    type = "Application";
    categories = [ "Network" ];
  };

  xdg.desktopEntries."vpn-zone-forget" = {
    name = "Сбросить сети программ";
    comment = "Забыть, в какой сети запускать программу — у одной или у всех сразу";
    exec = guiExec "forget";
    icon = "edit-clear-history";
    terminal = false;
    type = "Application";
    categories = [ "Network" ];
  };

  # Тот самый пункт в лаунчере (Super+Space → «VPN»).
  xdg.desktopEntries."vpn-zone-add" = {
    name = "Добавить VPN-зону (AmneziaWG)";
    comment = "Выбрать .conf и создать сетевую зону; ко всем приложениям появятся ярлыки «(имя зоны)»";
    exec = guiExec "add";
    icon = "network-vpn";
    terminal = false;
    type = "Application";
    categories = [ "Network" ];
  };
  };
}
