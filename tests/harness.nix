# Автономная тестовая обвязка: собирает home-manager-конфигурацию с модулем
# vpn-zones БЕЗ flake-инпутов (у flake.nix их нет намеренно). nixpkgs и
# home-manager пинуются в tests/pins.nix — конкретный коммит стабильной ветки с
# явным sha256, сборка воспроизводима и не едет вслед за веткой. Оттуда же пины
# берёт и VM-тест (tests/vm.nix).
#
# Использование:
#   nix-instantiate tests/harness.nix -A activationPackage        # только eval
#   nix-build tests/harness.nix -A scripts.vpn-zone               # адресная сборка
#   nix-build tests/harness.nix -A zoneHolder \
#     --argstr username "$(id -un)" --argstr homeDirectory "$HOME"
{
  username ? "runner",
  homeDirectory ? "/home/runner",
  system ? builtins.currentSystem,
}:

let
  pins = import ./pins.nix;
  nixpkgsSrc = pins.nixpkgs;
  homeManagerSrc = pins.home-manager;

  pkgs = import nixpkgsSrc {
    inherit system;
    config = { };
    overlays = [ ];
  };
  inherit (pkgs) lib;

  # Не-flake вход home-manager: modules/default.nix принимает { configuration,
  # pkgs, … } и возвращает { config, options, activationPackage, … }.
  hm = import "${homeManagerSrc}/modules" {
    inherit pkgs;
    configuration =
      { ... }:
      {
        imports = [ ../module ];
        programs.vpn-zones.enable = true;
        home = {
          inherit username homeDirectory;
          # Фиксируем: тестовая конфигурация всегда «свежая», миграций нет.
          stateVersion = "26.05";
        };
      };
  };

  # Скрипты модуля — внутренние let-биндинги, наружу они попадают только через
  # home.packages. Вытаскиваем их оттуда по имени деривации (lib.getName
  # отбрасывает версию: «vpn-zone-rust-0.1.0» → «vpn-zone-rust»), чтобы CI мог
  # собирать каждый адресно, не собирая activationPackage целиком.
  #
  # Список короткий, и это результат: shell в модуле остался ровно тремя
  # двухстрочными обёртками над бинарями крейта. Пикер, шесть GUI-ярлыков, обе
  # песочницы и сам CLI — теперь подкоманды и бинари vpn-zone-rust, а он
  # собирается своим job'ом. Ярлычный бинарь vpn-zone-gui в home.packages не
  # кладётся вовсе (его зовут .desktop-записи store-путём), поэтому и вытащить
  # его отсюда нельзя.
  scriptNames = [
    "vpn-zone"
    "vpn-zone-pick"
    "vpn-zone-sync"
  ];

  scriptByName =
    name:
    let
      matches = lib.filter (p: lib.getName p == name) hm.config.home.packages;
    in
    if matches == [ ] then
      throw "tests/harness.nix: в home.packages модуля нет скрипта «${name}» — список scriptNames разошёлся с module/default.nix"
    else
      lib.head matches;

  # ExecStart шаблонного юнита vpn-zone@ — строка вида
  # «/nix/store/…/bin/vpn-zone-core zone-holder --ip … --pasta … %i»: держатель
  # переехал в rust-крейт, а пути инструментов подставляет модуль. Берём строку
  # именно отсюда: интерполяция сохраняет ей контекст ВСЕХ store-путей, поэтому
  # обёртка ниже тянет за собой и ip, и pasta, и awg/wg.
  # Тип юнит-опций home-manager коэрсит значение в список (повторяемые ключи
  # ini) — нормализуем обратно в строку.
  rawExecStart = hm.config.systemd.user.services."vpn-zone@".Service.ExecStart;
  zoneHolderExecLine = if lib.isList rawExecStart then lib.head rawExecStart else rawExecStart;
in
{
  # Полная активация home-manager: инстанцируется в CI как «модуль хотя бы
  # целиком вычисляется». Собирать её не обязательно.
  inherit (hm) activationPackage;

  # Каждый скрипт — отдельным атрибутом: nix-build tests/harness.nix -A scripts.<имя>
  scripts = lib.genAttrs scriptNames scriptByName // {
    recurseForDerivations = true;
  };

  # Строка ExecStart юнита vpn-zone@ (для диагностики):
  #   nix-instantiate --eval tests/harness.nix -A zoneHolderExec
  zoneHolderExec = zoneHolderExecLine;

  # Запускаемая обёртка над держателем зоны: `zone-holder <имя-зоны>` делает то
  # же, что systemd-юнит vpn-zone@<имя>, но без systemd — на CI-раннере юнит не
  # установлен, а смоук-тесту зону поднимать надо.
  #
  # Строка подставляется БЕЗ кавычек намеренно: в ней несколько слов (бинарь,
  # подкоманда и флаги с путями), и словоделение bash — ровно то, что нужно;
  # пробелов внутри store-путей не бывает. Убираем из неё «%i» и подставляем
  # имя зоны своим аргументом.
  zoneHolder = pkgs.writeShellScriptBin "zone-holder" ''
    exec ${lib.replaceStrings [ " %i" ] [ "" ] zoneHolderExecLine} "''${1:?нужно имя зоны}"
  '';

  # Инструменты для смоук-теста — теми же версиями, что использует модуль.
  # Именно buildEnv, а не отдельные пакеты: util-linux и iproute2 многовыходные,
  # и `nix-build -o link` даёт ссылку на дефолтный output, в котором bin/ может
  # не быть — смоук на раннере так и упал («util-linux/bin/unshare: No such
  # file»). buildEnv собирает bin/ всех инструментов в один выход.
  smokeTools = pkgs.buildEnv {
    name = "vpn-zones-smoke-tools";
    paths = with pkgs; [
      wireguard-tools
      iproute2
      util-linux
      passt
      # Второй эшелон (docs/LEAK-MODEL.md): смоуку нужен nft, чтобы прочитать
      # `nft list ruleset` ВНУТРИ обоих namespace зоны. Сама зона получает свой
      # путь к nft флагом ExecStart, отсюда — только читалка.
      nftables
      # Не для самой зоны: coreutils нужен КОМАНДЕ ВНУТРИ песочницы ФС — там
      # своя /tmp и никакого /usr, поэтому `ls` обязан быть store-путём. Раньше
      # он грепался из текста shell-скрипта vpn-zone, а тот теперь бинарь.
      coreutils
    ];
    pathsToLink = [ "/bin" ];
  };

  # Обвязка для смоука ЗОНЫ OPENCONNECT — отдельным атрибутом, а не внутри
  # smokeTools: замыкание ocserv никому, кроме этой части теста, не нужно.
  #
  # Что зачем:
  #   • ocserv — настоящий сервер AnyConnect, поднимается на раннере под sudo
  #     (ему нужен свой tun в сети хоста) с самоподписанным сертификатом,
  #     который генерируется на лету. В git ни ключей, ни сертификатов;
  #   • openconnect — тот же клиент, что поедет пользователю. Смоук зовёт его
  #     ОДИН раз до создания зоны, чтобы спросить у него самого отпечаток
  #     сертификата («--servercert pin-sha256:…» он печатает в подсказке):
  #     считать отпечаток своими руками значит однажды разойтись с ним в
  #     формате;
  #   • openssl — сертификат, ключ и crypt-хеш пароля для plain-аутентификации
  #     ocserv (формат файла — username:группы:crypt(3)).
  ocTools = pkgs.buildEnv {
    name = "vpn-zones-oc-tools";
    paths = with pkgs; [
      ocserv
      openconnect
      openssl
    ];
    pathsToLink = [ "/bin" ];
  };

  # Окружение для rust-джоба CI: `nix-shell tests/harness.nix -A rustShell`.
  # Именно отсюда, а не `nix-shell -p`: у раннера нет канала <nixpkgs>
  # (install-nix-action его не ставит), а главное — компилятор и clippy
  # пинуются тем же nixpkgs, что и всё остальное, и CI не краснеет сам по
  # себе от обновления линтера в unstable.
  rustShell = pkgs.mkShell {
    packages = with pkgs; [
      cargo
      rustc
      clippy
      rustfmt
      pkg-config
      libseccomp
    ];
  };
}
