# Автономная тестовая обвязка: собирает home-manager-конфигурацию с модулем
# vpn-zones БЕЗ flake-инпутов (у flake.nix их нет намеренно). nixpkgs и
# home-manager пинуются здесь, по конкретному коммиту стабильной ветки с явным
# sha256 — сборка воспроизводима и не едет вслед за веткой.
#
# Обновление пинов:
#   git ls-remote https://github.com/NixOS/nixpkgs refs/heads/nixos-XX.YY
#   nix-prefetch-url --unpack https://github.com/NixOS/nixpkgs/archive/<rev>.tar.gz
#   (и то же для home-manager, ветка release-XX.YY)
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
  # nixpkgs, ветка nixos-26.05
  nixpkgsSrc = builtins.fetchTarball {
    name = "nixpkgs-nixos-26.05-062346a6";
    url = "https://github.com/NixOS/nixpkgs/archive/062346a6d85bc4b49dfaa61c986e9c5be21217d1.tar.gz";
    sha256 = "063ximydq4y927a6vq6aajvznf0mdyxnv4z29q8j09jiss5q5585";
  };

  # home-manager, ветка release-26.05 (в пару к nixpkgs выше)
  homeManagerSrc = builtins.fetchTarball {
    name = "home-manager-release-26.05-65258d5c";
    url = "https://github.com/nix-community/home-manager/archive/65258d5c65a250189fde2e35f490d15e064c4c62.tar.gz";
    sha256 = "1qsx6l8z2v2rzr47chfqvmr9585lcrb2wihixbklmz63nhsba6sb";
  };

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
  # отбрасывает версию: «wl-sandbox-1» → «wl-sandbox»), чтобы CI мог собирать
  # каждый адресно, не собирая activationPackage целиком.
  scriptNames = [
    "vpn-zone"
    "vpn-zone-pick"
    "vpn-zone-sync"
    "vpn-fs-sandbox"
    "wl-sandbox"
    "vpn-zone-add-gui"
    "vpn-zone-remove-gui"
    "vpn-zone-profile-rm-gui"
    "vpn-zone-profile-add-gui"
    "vpn-zone-settings-gui"
    "vpn-zone-forget-gui"
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

  # ExecStart шаблонного юнита vpn-zone@ — строка «/nix/store/…-vpn-zone-holder %i».
  # Сам держатель (writeShellScript) из let-биндингов модуля недоступен, поэтому
  # берём его отсюда: интерполяция сохраняет строке контекст store-пути.
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
    ];
    pathsToLink = [ "/bin" ];
  };
}
