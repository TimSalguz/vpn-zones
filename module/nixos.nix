# СИСТЕМНЫЙ УРОВЕНЬ cellward (прежнее имя — vpn-zones; ROADMAP M10, docs/SYSTEM.md,
# docs/ARCHITECTURE.ru.md). Единый вход programs.cellward.enable — в ./entry.nix.
#
# Та же зона, что у пользовательского уровня, — namespace, где есть только lo и
# туннель, — но держит её systemd с загрузки, а не сеанс. К ней подключаются
# системные службы и NixOS-контейнеры, которым нужна сеть «только через VPN»
# даже тогда, когда в систему никто не вошёл (торрент-клиент, Syncthing).
#
# Модуль необязательный и от домашнего не зависит: без него всё остаётся
# rootless, как было. Ключи зон в Nix не объявляются: конфиг лежит локально в
# /var/lib/vpn-zones/system/<имя>/config.conf (0600, root), либо `configFile`
# указывает на расшифрованный секрет (sops-nix, agenix).
#
# Что создаётся на каждую зону:
#   vpn-zone-system-ns-<имя>  namespace /run/netns/vz-<имя>: lo, второй эшелон,
#                             пустой resolv.conf. НЕ перезапускается при switch —
#                             иначе каждое обновление пакета выдёргивало бы
#                             namespace из-под всех, кто в нём живёт;
#   vpn-zone-system-<имя>     туннель: создаётся в сети хоста (там и остаётся
#                             его UDP-сокет), переезжает в зону как awg0; потом
#                             зеркало состояния в /run/vpn-zones/system/<имя>/.
#
# Службы и контейнеры привязаны к namespace (bindsTo), а за туннелем только
# идут следом (wants/after): упал туннель — у них остаётся один lo и ни одного
# пути наружу; пропал namespace — они останавливаются, потому что процесс в
# удалённом namespace отрезан насовсем.
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.cellward.system;

  # Every option of services.cellward.system, by its path below it: each also
  # answers to its old name under services.vpn-zones.system, with a warning
  # (the project was vpn-zones until 2026-09). One rename per option — a
  # renamed subtree would be one option of an empty submodule type.
  # tests/harness.nix checks that this list names every option.
  renamedOptions = [
    "enable"
    "switchGroup"
    "users"
    "zones"
    "services"
    "containers"
    "console.enable"
    "console.zone"
    "console.fallback"
    "console.admin"
    "egress.enable"
    "egress.mode"
    "egress.localNetworks"
    "egress.allowUsers"
    "egress.allowGroups"
    "egress.emergency.minutes"
    "egress.emergency.group"
    "host.nix"
    "host.dns"
    "host.time"
    "amneziawg"
  ];

  vpn-zone-rust = pkgs.callPackage ../package.nix { };
  # The same patched pasta as the user tier's (module/default.nix): a TCP
  # connection it cannot bind to the outbound interface is reset.
  passtPatched = pkgs.passt.overrideAttrs (old: {
    nativeBuildInputs = (old.nativeBuildInputs or [ ]) ++ [ pkgs.perl ];
    postPatch = (old.postPatch or "") + ''
      perl ${./patches/passt-bind-outbound-fatal.pl} < tcp.c > tcp.c.new
      mv tcp.c.new tcp.c
    '';
  });
  core = "${vpn-zone-rust}/bin/vpn-zone-core";
  # Абсолютные пути, как у пользовательского держателя: часть команд идёт
  # через `ip netns exec`, и PATH там ни при чём.
  tools = lib.concatStringsSep " " [
    "--ip ${pkgs.iproute2}/bin/ip"
    "--awg ${pkgs.amneziawg-tools}/bin/awg"
    "--wg ${pkgs.wireguard-tools}/bin/wg"
    "--nft ${pkgs.nftables}/bin/nft"
    "--pasta ${passtPatched}/bin/pasta"
  ];

  # Шаблоны: зона — экземпляр, так что зону можно добавить и без пересборки
  # (vpn-zone-sys --add), а объявленные отличаются только настройками в /etc.
  nsUnit = zone: "vpn-zone-system-ns@${zone}";
  holderUnit = zone: "vpn-zone-system@${zone}";
  netnsPath = zone: "/run/netns/vz-${zone}";
  resolvPath = zone: "/etc/netns/vz-${zone}/resolv.conf";

  # То же правило, что system::check_name в крейте: vz-<имя> — это ещё и имя
  # интерфейса в сети хоста, а их длина кончается на 15.
  validName =
    name:
    builtins.match "[a-z0-9][a-z0-9-]{0,11}" name != null
    && !(builtins.elem name [
      "unconfined"
      "direct"
      "offline"
    ]);

  # Метка «vpn-zones выключены»: её ставит vpn-zones-off, снимает vpn-zones-on.
  # Пока она есть, не поднимаются ни зоны, ни политика хоста, а генератор не
  # привязывает службы — всё в сети хоста, до следующего vpn-zones-on, в том
  # числе после перезагрузки.
  offFlag = "/var/lib/vpn-zones/off";
  # Куда хост спрашивает имена при host.dns: не 127.0.0.53/54 (resolved).
  hostDnsAddress = "127.0.0.60";
  hostDnsListen = "${hostDnsAddress}:53";
  systemctl = "${config.systemd.package}/bin/systemctl";

  # Дополнение к юниту службы, которое кладёт генератор (см. «Службы в зоне»).
  attachDropIn =
    unit: s:
    pkgs.writeText "vpn-zones-attach-${unit}.conf" (
      ''
        [Unit]
        BindsTo=${nsUnit s.zone}.service
        After=${nsUnit s.zone}.service${lib.optionalString (s.afterHolder or true) " ${holderUnit s.zone}.service"}
        Wants=${holderUnit s.zone}.service

        [Service]
        NetworkNamespacePath=${netnsPath s.zone}
        # Без «-»: нет файла — служба не стартует, а не резолвит через хост.
        BindReadOnlyPaths=${resolvPath s.zone}:/etc/resolv.conf
        # hosts: files dns — ни один модуль NSS, кроме обычного резолвера.
        BindReadOnlyPaths=/etc/netns/vz-${s.zone}/nsswitch.conf:/etc/nsswitch.conf
        # unix-сокеты проходят сквозь сетевые пространства: nscd, resolved и
        # avahi ответили бы из сети хоста, мимо туннеля.
        InaccessiblePaths=-/run/nscd -/run/systemd/resolve/io.systemd.Resolve -/run/avahi-daemon
      ''
      + lib.optionalString (!s.systemBus) ''
        InaccessiblePaths=-/run/dbus/system_bus_socket
      ''
      + (s.extra or "")
    );

  # Службы в зонах: названные человеком и службы самого хоста (host.*).
  attachedServices =
    cfg.services
    // lib.optionalAttrs (cfg.host.nix != null) {
      nix-daemon = {
        zone = cfg.host.nix;
        systemBus = false;
        # Не ждать выхода зоны: пространство уже есть, сеть в нём появится
        # вместе с туннелем, а локальная сборка VPN не ждёт никогда.
        afterHolder = false;
      };
    }
    // lib.optionalAttrs (cfg.host.dns != null) {
      # В зоне — спрашивать резолверы зоны (её resolv.conf привязан поверх
      # /etc/resolv.conf выше); без привязки (выключено) остаётся ExecStart
      # юнита — адреса напрямую из сети хоста.
      vpn-zones-dns = {
        zone = cfg.host.dns;
        systemBus = false;
        afterHolder = false;
        extra = ''
          ExecStart=
          ExecStart=${core} dns-forward --resolv /etc/resolv.conf
        '';
      };
    }
    // lib.optionalAttrs (cfg.host.time != null) {
      # Шина — да: timesyncd без неё не запускается (держит имя
      # org.freedesktop.timesync1), а имена он спрашивает через NSS зоны.
      systemd-timesyncd = {
        zone = cfg.host.time;
        systemBus = true;
        # timesyncd — из ранней загрузки (Before=sysinit.target), а выход
        # зоны ждёт сеть: порядок «после выхода» дал бы цикл.
        afterHolder = false;
        # Сам он не переспросит: о сети судит по состоянию сети хоста, и
        # после неудачных первых попыток (в зоне ещё один lo) ждёт события,
        # которого может не быть (CI: ни одной попытки за 2 минуты). Выход
        # зоны, поднявшись, перезапускает его.
        restartWhenUp = true;
      };
    };

  # Выход зоны, поднявшись, перезапускает службу (restartWhenUp): для тех,
  # кто стартует раньше выхода и сам сеть не переспрашивает.
  restartWhenUpDropIn =
    unit:
    pkgs.writeText "vpn-zones-restart-when-up-${unit}.conf" ''
      [Service]
      ExecStartPost=-${systemctl} --no-block try-restart ${unit}.service
    '';

  consumerDeps = zone: {
    bindsTo = [ "${nsUnit zone}.service" ];
    after = [
      "${nsUnit zone}.service"
      "${holderUnit zone}.service"
    ];
    wants = [ "${holderUnit zone}.service" ];
  };

  zoneOpts = {
    options = {
      kind = lib.mkOption {
        type = lib.types.enum [
          "tunnel"
          "plain"
        ];
        default = "tunnel";
        description = ''
          `tunnel`: WireGuard/AmneziaWG, the config from `configFile` or the
          state directory. `plain`: no tunnel — out through the host's own
          network by pasta, not encrypted by the zone, but a namespace of its
          own with its own resolvers and nothing of the host's. For the TTY
          console when the VPN cannot come up, and for programs that have to
          go out directly once the host has no network of its own (`egress`).
        '';
      };
      configFile = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "/run/secrets/vpn-nl";
        description = ''
          Where the zone's WireGuard/AmneziaWG config is at run time, when it is
          not `/var/lib/vpn-zones/system/<name>/config.conf`. A string and not a
          path on purpose: a path would be copied into the world-readable Nix
          store together with the private key. Point it at a decrypted secret
          and list the holder in that secret's `restartUnits`.
        '';
      };
      uplink = lib.mkOption {
        # An interface's name as the kernel allows it: 1–15 characters, no
        # slash, no space. Anything else — an empty string too — would have
        # been "no uplink", out by the host's routes (review 2026-09-25).
        type = lib.types.nullOr (lib.types.strMatching "[A-Za-z0-9_.:@-]{1,15}");
        default = null;
        example = "enp4s0";
        description = ''
          The one interface of the host the zone goes out through — for two
          providers, say (docs/SYSTEM.md §4a). A tunnel zone then gets an
          uplink namespace of its own, `vzu-<name>`, behind pasta bound to the
          interface, and its tunnel is born there; a plain zone's pasta is
          bound to it. Out by that interface or not at all: down or gone, the
          zone has no way out, never another route. `null`: wherever the
          host routes.
        '';
      };
      dns = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [ "192.168.1.1" ];
        description = ''
          The zone's own resolvers, asked through its way out: instead of the
          config's `DNS =`, or for a plain zone instead of the public ones
          (1.1.1.1, 9.9.9.9) — the router, say. Addresses only.
        '';
      };
      autoStart = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Bring the zone up at boot. Otherwise it comes up when something bound to it starts, or with `systemctl start vpn-zone-system-<name>`.";
      };
      users = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [ "alice" ];
        description = ''
          Users who may run console programs in this zone with
          `vpn-zone-sys <name> -- <command>`. The program runs as the user,
          with the zone's network and resolvers, without the session's sockets
          and with no way to gain privileges. Empty: nobody.
        '';
      };
      systemBus = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Leave the host's system bus reachable to programs run with
          `vpn-zone-sys`. Off by default for the same reason as for services:
          systemd-resolved answers name lookups over it, around the tunnel.
        '';
      };
    };
  };

  serviceOpts = {
    options = {
      zone = lib.mkOption {
        type = lib.types.str;
        description = "The system zone the service runs in.";
      };
      systemBus = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Leave the host's system bus reachable. Off by default: systemd-resolved
          answers name lookups over it (`org.freedesktop.resolve1`), in the
          host's network, around the tunnel.
        '';
      };
    };
  };

  # Кто вообще ходит через посредника: у сокета группа vpn-zones, а список
  # по зонам посредник проверяет сам.
  runUsers = lib.unique (
    cfg.users ++ lib.concatMap (z: z.users) (lib.attrValues cfg.zones)
  );

  # pasta одной или нескольких простых зон: системный пользователь, а не root и
  # не nobody — политика хоста пропускает системных, и этого знает по имени.
  plainUser = "vpn-zones-plain";

  containerOpts = {
    options.zone = lib.mkOption {
      type = lib.types.str;
      description = "The system zone the NixOS container runs in.";
    };
  };
in
{
  # Политика WirePlumber для PipeWire зон (docs/LEAK-MODEL.md §20): от
  # системных зон не зависит — нужна пользовательскому уровню.
  imports = [
    ./wireplumber/nixos.nix
    # The single entry, programs.cellward.enable.
    ./entry.nix
  ]
  ++ map (
    name:
    lib.mkRenamedOptionModule (lib.splitString "." "services.vpn-zones.system.${name}") (
      lib.splitString "." "services.cellward.system.${name}"
    )
  ) renamedOptions;

  options.services.cellward.system = {
    enable = lib.mkEnableOption "system zones of cellward: network namespaces with a tunnel as their only way out, held from boot, for services and NixOS containers";

    switchGroup = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = "wheel";
      description = ''
        Members may run `vpn-zones-off` with their password — at the machine
        too: a line a zone's program slips into the shell's startup would
        otherwise switch the protection off at the next login — and
        `vpn-zones-on` without one at the machine itself (a process in a local,
        active login session's own scope), with it from anywhere else:
        cellward off entirely — zones, the egress policy, services back on the
        host's network — with no rebuild and no network, until turned on again.
        This turns polkit on. `null`: root only.
      '';
    };

    users = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "alice" ];
      description = ''
        Users who may add system zones on the spot (`vpn-zone-sys --add`) and
        see their state; a zone's own `users` may use it. Everybody listed here
        or in any zone's `users` is in the group `vpn-zones`.
      '';
    };

    zones = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule zoneOpts);
      default = { };
      example = lib.literalExpression ''{ nl = { }; work.configFile = "/run/secrets/vpn-work"; }'';
      description = "The system zones. A name is 1 to 12 of a-z, 0-9 and '-'.";
    };

    services = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule serviceOpts);
      default = { };
      example = lib.literalExpression ''{ qbittorrent.zone = "nl"; }'';
      description = ''
        System services to run in a zone, by their `systemd.services` name. The
        service gets the zone's network namespace and resolv.conf; nscd,
        resolved's varlink socket and (unless `systemBus`) the system bus are
        hidden from it, because each of them resolves names through the host.
      '';
    };

    containers = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule containerOpts);
      default = { };
      example = lib.literalExpression ''{ torrent.zone = "nl"; }'';
      description = ''
        NixOS containers (`containers.<name>`) to run in a zone. The container
        gets the zone's network namespace and resolv.conf, its own user
        namespace (`privateUsers = "pick"`, so its root can't touch the zone's
        routes) and no access to the host's Nix daemon, which would otherwise
        download anything it is asked to in the host's network.
      '';
    };

    console = {
      enable = lib.mkEnableOption ''
        the TTY console (docs/SYSTEM.md §7a): logging in on a text console
        lands in a small menu with a network already — a terminal in `zone`
        with one key, the plain `fallback` zone when the VPN does not come up,
        the admin tool, the emergency key, the plain console. For the users of
        `zone`; everybody else gets the ordinary login'';
      zone = lib.mkOption {
        type = lib.types.str;
        example = "nl";
        description = "The system zone the console's terminal runs in. Its `users` get the console.";
      };
      fallback = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "direct";
        description = "A plain zone offered when `zone` has no live tunnel.";
      };
      admin = lib.mkOption {
        type = lib.types.nullOr (
          lib.types.submodule {
            options = {
              command = lib.mkOption {
                type = lib.types.str;
                description = "Run on the host, as the user.";
              };
              label = lib.mkOption {
                type = lib.types.str;
                description = "What the menu calls it.";
              };
            };
          }
        );
        default = null;
        example = lib.literalExpression ''{ command = "nix_cm --tui"; label = "Настройки и откат"; }'';
        description = "An admin tool behind the `n` key.";
      };
    };

    egress = {
      enable = lib.mkEnableOption ''
        the host egress policy (docs/SYSTEM.md §9): a user's program outside
        every zone does not reach the network. Root, system users, the uplinks
        of user zones, system zones and everything inside a zone are not
        affected'';
      mode = lib.mkOption {
        type = lib.types.enum [
          "audit"
          "enforce"
          "strict"
        ];
        default = "audit";
        description = ''
          `audit` logs what would be refused and lets it through — watch the
          kernel log for `vpn-zones-egress:` before switching; `enforce`
          refuses it; `strict` refuses it and keeps root and the system's
          users to `localNetworks` and DHCP as well: what of the system has to
          reach further goes through a zone (`host.nix`, `host.time`,
          `services.<unit>`).
        '';
      };
      localNetworks = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [
          "10.0.0.0/8"
          "172.16.0.0/12"
          "192.168.0.0/16"
          "169.254.0.0/16"
          "224.0.0.0/4"
          "255.255.255.255/32"
          "fe80::/10"
          "fc00::/7"
          "ff00::/8"
        ];
        description = ''
          What `strict` leaves to root and the system's users: the router, the
          printer, the resolver on the local network. Private, link-local and
          multicast ranges by default; a local network on public addresses has
          to be added here.
        '';
      };
      allowUsers = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = [ "alice" ];
        description = "Users whose own programs still go out directly — for moving over one person at a time.";
      };
      allowGroups = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = lib.optional (cfg.egress.mode != "strict") "nixbld";
        defaultText = lib.literalExpression ''lib.optional (mode != "strict") "nixbld"'';
        description = ''
          Groups whose programs go out directly. `nixbld`: builds that fetch —
          not under `strict`, where the Nix daemon downloads through `host.nix`
          and its builds with it.
        '';
      };
      emergency = {
        minutes = lib.mkOption {
          type = lib.types.ints.positive;
          default = 15;
          description = "How long `vpn-zones-egress-open.service` lifts the policy before it puts it back.";
        };
        group = lib.mkOption {
          type = lib.types.nullOr lib.types.str;
          default = "wheel";
          description = "Members may start `vpn-zones-egress-open.service` with their password (at the machine too), and stop it — which only closes the host again — without one at the machine itself (a process in a local, active login session's own scope, the TTY included). This turns polkit on. `null`: root only.";
        };
      };
    };

    host = {
      nix = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "direct0";
        description = ''
          The system zone the Nix daemon downloads through: substitutes and the
          builds that fetch run in the daemon's network. A plain zone is
          "directly"; a VPN zone takes the downloads through the tunnel. `null`:
          the host's own network, which `egress.mode = "strict"` closes to it.
          The daemon starts without its zone's tunnel too (the zone's namespace
          is enough), so local builds never wait for a VPN.
        '';
      };
      dns = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "direct0";
        description = ''
          The system zone the host's own names are asked through
          (docs/SYSTEM.md §9c). A forwarder listens on 127.0.0.60:53 in the
          host's network and asks the zone's resolvers from the zone's; the
          host's resolver — resolved, or /etc/resolv.conf without it — is
          pointed there and nowhere else: its DNS, FallbackDNS and Domains are
          replaced, NetworkManager's and dhcpcd's resolvers are ignored. A
          plain zone is "directly"; a VPN zone must then have its endpoint as
          an address, since its name would be asked through the zone itself.
          Off (`vpn-zones-off`), the forwarder asks the zone's `dns`, or the
          public resolvers, from the host's network.
        '';
      };
      time = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "direct0";
        description = ''
          The system zone systemd-timesyncd sets the clock through. A plain
          zone is "directly"; a VPN zone hides who asks for the time. `null`:
          the host's own network, which `egress.mode = "strict"` closes to it.
        '';
      };
    };

    amneziawg = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Load the out-of-tree amneziawg kernel module (built for the running
        kernel), with `enable` or with the single entry `programs.cellward.enable`
        — the user tier's zones need it too. Without it only configs with no
        obfuscation parameters work, through the in-tree wireguard module.
      '';
    };
  };

  config = lib.mkIf cfg.enable (
    lib.mkMerge [
      {
        assertions =
          lib.mapAttrsToList (name: _: {
            assertion = validName name;
            message = "services.cellward.system.zones.${name}: a system zone is named by 1 to 12 of a-z, 0-9 and '-', not starting with '-', and not unconfined, direct or offline.";
          }) cfg.zones
          ++ lib.mapAttrsToList (name: z: {
            assertion = z.kind != "plain" || z.configFile == null;
            message = "services.cellward.system.zones.${name}: a plain zone has no tunnel, so no configFile.";
          }) cfg.zones
          # A plain zone through one interface asks names of its own resolvers:
          # the defaults are the host's primary network's view, and queries
          # meant for one network would go out through the other — linking the
          # two (review 2026-09-25).
          ++ lib.mapAttrsToList (name: z: {
            assertion = !(z.kind == "plain" && z.uplink != null) || z.dns != [ ];
            message = "services.cellward.system.zones.${name}: a plain zone with an uplink needs its own dns — resolvers reached through ${toString z.uplink}.";
          }) cfg.zones
          ++ lib.mapAttrsToList (unit: s: {
            assertion = cfg.zones ? ${s.zone};
            message = "services.cellward.system.services.${unit}.zone = \"${s.zone}\": there is no such zone in services.cellward.system.zones.";
          }) cfg.services
          ++ lib.concatLists (
            lib.mapAttrsToList
              (
                what: unit:
                lib.optionals (cfg.host.${what} != null) [
                  {
                    assertion = cfg.zones ? ${cfg.host.${what}};
                    message = "services.cellward.system.host.${what} = \"${cfg.host.${what}}\": there is no such zone in services.cellward.system.zones.";
                  }
                  {
                    assertion = !(cfg.services ? ${unit});
                    message = "services.cellward.system.host.${what} and services.cellward.system.services.${unit} both put ${unit} into a zone: one of them.";
                  }
                ]
              )
              {
                nix = "nix-daemon";
                time = "systemd-timesyncd";
                dns = "vpn-zones-dns";
              }
          )
          ++ lib.concatLists (
            lib.mapAttrsToList (
              name: z:
              map (a: {
                # Строже, чем проверит программа (она пропустит только адрес):
                # опечатка должна остановить сборку, а не молча выпасть.
                assertion = builtins.match "[0-9a-fA-F.:]+" a != null;
                message = "services.cellward.system.zones.${name}.dns: \"${a}\" is not an address.";
              }) z.dns
            ) cfg.zones
          )
          ++ lib.mapAttrsToList (name: z: {
            # Как проверит программа (`hostif::valid_interface_name`): имя
            # интерфейса Linux, 1–15 байт, без `/`, `:` и пробелов.
            assertion = z.uplink == null || builtins.match "[^/: \t\n]{1,15}" z.uplink != null;
            message = "services.cellward.system.zones.${name}.uplink: \"${toString z.uplink}\" is not an interface name.";
          }) cfg.zones
          ++ [
            {
              assertion = cfg.host.time == null || config.services.timesyncd.enable;
              message = "services.cellward.system.host.time is for systemd-timesyncd, which is off here; another time daemon goes into a zone with services.cellward.system.services.<unit>.";
            }
          ]
          ++ lib.concatLists (
            lib.mapAttrsToList (
              c: a:
              let
                ct = config.containers.${c};
              in
              [
                {
                  assertion = cfg.zones ? ${a.zone};
                  message = "services.cellward.system.containers.${c}.zone = \"${a.zone}\": there is no such zone in services.cellward.system.zones.";
                }
                {
                  # Без своего user namespace root контейнера — root и в
                  # namespace зоны: мог бы добавить маршрут или интерфейс мимо
                  # туннеля.
                  assertion =
                    !(builtins.elem ct.privateUsers [
                      "no"
                      "identity"
                      0
                    ]);
                  message = "containers.${c} runs in the system zone ${a.zone}: its privateUsers must give it a user namespace of its own (\"pick\" or a range), or its root could route around the tunnel.";
                }
                {
                  assertion = !ct.enableTun && !(builtins.elem "CAP_NET_ADMIN" ct.additionalCapabilities);
                  message = "containers.${c} runs in the system zone ${a.zone}: no enableTun and no CAP_NET_ADMIN — a network of its own is exactly what the zone takes away.";
                }
                {
                  # Сеть контейнера — сеть зоны, в которой запущен nspawn:
                  # любой из этих флагов дал бы ему другую.
                  assertion =
                    !ct.privateNetwork
                    && ct.networkNamespace == null
                    && ct.interfaces == [ ]
                    && ct.macvlans == [ ]
                    && ct.extraVeths == { };
                  message = "containers.${c} runs in the system zone ${a.zone}: its network is the zone's, so privateNetwork, networkNamespace, interfaces, macvlans and extraVeths have to stay unset.";
                }
              ]
            ) cfg.containers
          );

        users.groups.vpn-zones.members = runUsers;
        # Всегда: простую зону можно добавить и на ходу.
        users.users.${plainUser} = {
          isSystemUser = true;
          group = plainUser;
          description = "cellward pasta of plain system zones";
        };
        users.groups.${plainUser} = { };
        # pasta пользовательских зон через системную: своя группа, чтобы
        # системная зона отказала её пакетам к своим же адресам (ревью).
        users.groups.vpn-zones-bridge = { };

        # Список для `cellward status --json` (system_networks), и по зоне —
        # кто может запускать в ней программы (посредник, rust/src/sysrun.rs).
        environment.etc = {
          "vpn-zones/system-zones".text = lib.concatMapStrings (name: name + "\n") (
            lib.attrNames cfg.zones
          );
          # Кто может добавлять зоны на ходу: `users`, и никто больше — у
          # пользователей зоны только право ею пользоваться (ревью).
          "vpn-zones/system-adders".text = lib.concatMapStrings (u: u + "\n") cfg.users;
        }
        # Зоны, через которые идут службы самого хоста: их конфиг запросом не
        # заменить — кто задаёт туннель, тот отвечает за имена, часы и службы
        # хоста (ревью).
        // lib.listToAttrs (
          map (z: lib.nameValuePair "vpn-zones/system-zones.d/${z}/carries" { text = "yes\n"; }) (
            lib.unique (
              lib.mapAttrsToList (_: s: s.zone) attachedServices
              ++ lib.mapAttrsToList (_: a: a.zone) cfg.containers
            )
          )
        )
        // lib.mapAttrs' (
          name: z:
          lib.nameValuePair "vpn-zones/system-zones.d/${name}/users" {
            text = lib.concatMapStrings (u: u + "\n") z.users;
          }
        ) cfg.zones
        // lib.mapAttrs' (
          name: _:
          lib.nameValuePair "vpn-zones/system-zones.d/${name}/system-bus" { text = "yes\n"; }
        ) (lib.filterAttrs (_: z: z.systemBus) cfg.zones)
        // lib.mapAttrs' (
          name: z: lib.nameValuePair "vpn-zones/system-zones.d/${name}/kind" { text = z.kind + "\n"; }
        ) cfg.zones
        // lib.mapAttrs' (
          name: z: lib.nameValuePair "vpn-zones/system-zones.d/${name}/uplink" { text = z.uplink + "\n"; }
        ) (lib.filterAttrs (_: z: z.uplink != null) cfg.zones)
        // lib.mapAttrs' (
          name: z:
          lib.nameValuePair "vpn-zones/system-zones.d/${name}/dns" {
            text = lib.concatMapStrings (a: a + "\n") z.dns;
          }
        ) (lib.filterAttrs (_: z: z.dns != [ ]) cfg.zones)
        // lib.mapAttrs' (
          name: z: lib.nameValuePair "vpn-zones/system-zones.d/${name}/config" { text = z.configFile + "\n"; }
        ) (lib.filterAttrs (_: z: z.configFile != null) cfg.zones);

        boot.extraModulePackages = lib.mkIf cfg.amneziawg [ config.boot.kernelPackages.amneziawg ];
        boot.kernelModules = lib.mkIf cfg.amneziawg [ "amneziawg" ];

        # Каталог запуска зоны — 2750 root:vpn-zones: группа читает состояние,
        # а новые файлы наследуют группу от setgid-каталога.
        systemd.tmpfiles.rules = [
          "d /run/vpn-zones 0755 root root -"
          "d /run/vpn-zones/system 0755 root root -"
          "d /var/lib/vpn-zones 0755 root root -"
          # 0755: имена и виды зон видны их пользователям; сами конфиги —
          # 0600 root.
          "d /var/lib/vpn-zones/system 0755 root root -"
        ]
        ++ lib.concatLists (
          lib.mapAttrsToList (name: _: [
            "d /run/vpn-zones/system/${name} 2750 root vpn-zones -"
            "d /var/lib/vpn-zones/system/${name} 0755 root root -"
          ]) cfg.zones
        );

        # Держатель сам читает настройки зоны: объявленной — из /etc, добавленной
        # на ходу — из /var/lib/vpn-zones/system/<имя>/. Юниту нужно одно имя.
        systemd.services."vpn-zone-system-ns@" = {
          description = "cellward: network namespace of the system zone %i";
          restartIfChanged = false;
          # Раннее: пространство нужно и службам ранней загрузки (timesyncd —
          # до sysinit.target). Ему хватает /run, /etc и стора — сети не надо;
          # но `ip netns` держит пространства в /var/run/netns, а ссылку
          # /var/run → /run делает tmpfiles (VM-тест: «mkdir /var/run/netns
          # failed»). Оба — тоже до sysinit.target, цикла нет.
          unitConfig.DefaultDependencies = false;
          after = [
            "local-fs.target"
            "systemd-tmpfiles-setup.service"
          ];
          before = [ "shutdown.target" ];
          conflicts = [ "shutdown.target" ];
          # vpn-zones-off и `vpnzones=off` в строке ядра: зоны не поднимаются.
          unitConfig.ConditionPathExists = "!${offFlag}";
          unitConfig.ConditionKernelCommandLine = "!vpnzones=off";
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            ExecStart = "${core} system-zone ns-up ${tools} %i";
            ExecStop = "${core} system-zone ns-down ${tools} %i";
          };
        };
        systemd.services."vpn-zone-system@" = {
          description = "cellward: the way out of the system zone %i";
          # Like its namespace: a switch does not restart the tunnel under
          # the services running in the zone — they would lose the network
          # for its whole restart. The zone takes the new build when it is
          # restarted.
          restartIfChanged = false;
          unitConfig.ConditionPathExists = "!${offFlag}";
          unitConfig.ConditionKernelCommandLine = "!vpnzones=off";
          bindsTo = [ "vpn-zone-system-ns@%i.service" ];
          after = [
            "vpn-zone-system-ns@%i.service"
            "network-online.target"
          ];
          wants = [ "network-online.target" ];
          serviceConfig = {
            # READY=1 — после настройки туннеля и resolv.conf зоны: всё,
            # что идёт следом, стартует уже с сетью, а не с одним lo.
            Type = "notify";
            ExecStart = "${core} system-zone up ${tools} %i";
            # После любой остановки, и после неудачного старта тоже:
            # туннель удалён, в зоне остаётся один lo.
            ExecStopPost = "${core} system-zone down ${tools} %i";
            # При загрузке endpoint может ещё не разрешаться.
            Restart = "on-failure";
            RestartSec = "10s";
          };
        };
        systemd.targets.multi-user.wants = map (name: "${holderUnit name}.service") (
          lib.attrNames (lib.filterAttrs (_: z: z.autoStart) cfg.zones)
        );
      }

      # --- СЛУЖБЫ В ЗОНЕ (этап 2) ---
      # Привязка — не опциями юнита, а дополнением в /run, которое кладёт
      # генератор systemd при каждой загрузке и daemon-reload. Так выключатель
      # (vpn-zones-off) возвращает службы в сеть хоста без пересборки: без
      # метки дополнений нет. Генератор — несколько строк sh с абсолютными
      # путями, без нашей программы: он должен работать, когда наше сломано.
      (lib.mkIf (attachedServices != { }) {
        systemd.generators.vpn-zones = pkgs.writeShellScript "vpn-zones-generator" (
          ''
            [ -e ${offFlag} ] && exit 0
            read -r cmdline < /proc/cmdline
            case " $cmdline " in *" vpnzones=off "*) exit 0 ;; esac
          ''
          + lib.concatStrings (
            lib.mapAttrsToList (
              unit: s:
              ''
                ${pkgs.coreutils}/bin/mkdir -p "$1/${unit}.service.d"
                ${pkgs.coreutils}/bin/ln -sf ${attachDropIn unit s} "$1/${unit}.service.d/50-vpn-zones.conf"
              ''
              + lib.optionalString (s.restartWhenUp or false) ''
                ${pkgs.coreutils}/bin/mkdir -p "$1/${holderUnit s.zone}.service.d"
                ${pkgs.coreutils}/bin/ln -sf ${restartWhenUpDropIn unit} "$1/${holderUnit s.zone}.service.d/50-vpn-zones-restart-${unit}.conf"
              ''
            ) attachedServices
          )
        );
      })

      # --- ПРОГРАММЫ ПОЛЬЗОВАТЕЛЕЙ В ЗОНЕ (этап 4, docs/SYSTEM.md §7) ---
      # Войти в пространство зоны без root нельзя, поэтому входит посредник:
      # по юниту на каждый запуск (Accept=yes), кто спрашивает — от ядра,
      # команда — уже от имени пользователя и с NO_NEW_PRIVS.
      {
        systemd.sockets.vpn-zone-sysrun = {
          description = "cellward: programs of users in system zones";
          wantedBy = [ "sockets.target" ];
          socketConfig = {
            ListenSequentialPacket = "/run/vpn-zones/sysrun.sock";
            SocketMode = "0660";
            SocketGroup = "vpn-zones";
            Accept = true;
            MaxConnections = 64;
            # Для AF_UNIX systemd считает источником uid собеседника: один
            # пользователь не займёт все 64 и не закроет посредника остальным
            # (ревью: 64 молчащих соединения — и пульт TTY без сети).
            MaxConnectionsPerSource = 16;
          };
        };
        systemd.services."vpn-zone-sysrun@" = {
          description = "cellward: a program in a system zone";
          serviceConfig = {
            ExecStart = "${core} system-run-service";
            StandardInput = "socket";
            StandardOutput = "journal";
            StandardError = "journal";
            Environment = [
              # «Добавить зону» и «поднять зону» — systemctl от root.
              "VPN_ZONE_SYSTEMCTL=${config.systemd.package}/bin/systemctl"
              # Выход пользовательской зоны через системную (SYSTEM.md §7b):
              # pasta в сети системной зоны, от имени пользователя.
              "VPN_ZONE_PASTA=${passtPatched}/bin/pasta"
            ];
            # Войти в пространство и смонтировать своё (SYS_ADMIN), стать
            # пользователем (SETUID, SETGID), погасить его программу или pasta,
            # когда клиент ушёл (KILL). Больше ничего: пространства
            # пользовательской зоны приходят дескрипторами, /proc чужих
            # процессов (SYS_PTRACE) не нужен.
            CapabilityBoundingSet = [
              "CAP_SYS_ADMIN"
              "CAP_SETUID"
              "CAP_SETGID"
              "CAP_KILL"
            ];
          };
        };
        environment.systemPackages = [
          (pkgs.writeShellScriptBin "vpn-zone-sys" ''
            exec ${core} system-run "$@"
          '')
        ];
      }

      # --- ИМЕНА ХОСТА ЧЕРЕЗ ЗОНУ (docs/SYSTEM.md §9c) ---
      # Сокеты открывает systemd в сети хоста, служба живёт в сети зоны:
      # вопрос приходит с хоста, дальше его задают уже из зоны.
      (lib.mkIf (cfg.host.dns != null) (
        let
          zone =
            cfg.zones.${cfg.host.dns} or {
              kind = "plain";
              dns = [ ];
            };
          # Без привязки (vpn-zones выключены) хост как обычный: резолверы
          # роутера, какие он знает; нет их — свои простой зоны, иначе
          # публичные. Свои резолверы VPN-зоны из сети хоста недостижимы.
          offFallback =
            if zone.kind == "plain" && zone.dns != [ ] then
              zone.dns
            else
              [
                "1.1.1.1"
                "9.9.9.9"
              ];
          networkdLeaks = lib.filterAttrs (
            _: n:
            let
              off = v: v == false || v == "no" || v == "false";
            in
            (n.networkConfig.DNS or [ ]) != [ ]
            || !(off (n.dhcpV4Config.UseDNS or true))
            || !(off (n.dhcpV6Config.UseDNS or true))
            || !(off (n.ipv6AcceptRAConfig.UseDNS or true))
          ) config.systemd.network.networks;
        in
        {
          systemd.sockets.vpn-zones-dns = {
            description = "cellward: the host's DNS, asked through the zone ${cfg.host.dns}";
            wantedBy = [ "sockets.target" ];
            listenDatagrams = [ hostDnsListen ];
            listenStreams = [ hostDnsListen ];
          };
          systemd.services.vpn-zones-dns = {
            description = "cellward: the host's DNS through a zone";
            serviceConfig = {
              ExecStart =
                "${core} dns-forward --host-resolvers"
                + lib.concatMapStrings (a: " --fallback ${a}") offFallback;
              DynamicUser = true;
              NoNewPrivileges = true;
              CapabilityBoundingSet = "";
              ProtectSystem = "strict";
              ProtectHome = true;
              PrivateTmp = true;
              PrivateDevices = true;
              RestrictAddressFamilies = [
                "AF_INET"
                "AF_INET6"
                "AF_UNIX"
              ];
              SystemCallArchitectures = "native";
              MemoryDenyWriteExecute = true;
            };
          };

          # Резолвер хоста — только сюда. DNS/FallbackDNS/Domains заменяются
          # целиком (mkForce): слитый список отправил бы часть вопросов мимо
          # зоны. Резолверы DHCP не доходят ни до resolved, ни до resolv.conf —
          # иначе вопросы пошли бы роутеру напрямую.
          services.resolved.settings.Resolve = lib.mkIf config.services.resolved.enable {
            DNS = lib.mkForce [ hostDnsAddress ];
            FallbackDNS = lib.mkForce [ ];
            Domains = lib.mkForce [ "~." ];
            # LLMNR и mDNS resolved спрашивает сам, многоадресно, в сети
            # хоста: односложные имена ушли бы в локальную сеть мимо зоны
            # (ревью). mkDefault — mDNS на `.local` кому-то нужен сознательно.
            LLMNR = lib.mkDefault "false";
            MulticastDNS = lib.mkDefault "false";
          };
          networking.nameservers = lib.mkIf (!config.services.resolved.enable) (
            lib.mkForce [ hostDnsAddress ]
          );
          # NM: не `dns = "none"` — ключ `systemd-resolved` (по умолчанию true)
          # и тогда отправляет resolved DNS каждого соединения. Так: свою копию
          # (/run/NetworkManager/resolv.conf — резолверы роутера для простых
          # зон и для выключенного состояния) пишет, остального не трогает.
          networking.networkmanager.dns = lib.mkIf config.networking.networkmanager.enable (
            lib.mkForce "default"
          );
          networking.networkmanager.settings.main = lib.mkIf config.networking.networkmanager.enable {
            rc-manager = lib.mkForce "unmanaged";
            systemd-resolved = lib.mkForce false;
          };
          # dhcpcd: не `nohook resolv.conf` в extraConfig — nixpkgs ставит его
          # после блоков `interface ethX` (статический IPv6), а блок в
          # dhcpcd.conf тянется до конца файла: хук пропускался бы на одном
          # интерфейсе (VM-тест: eth0 отдал resolved 10.0.2.3). enter-hook
          # выполняется в той же оболочке перед хуками, на каждом интерфейсе,
          # а список пропусков читается заново перед каждым хуком.
          environment.etc."dhcpcd.enter-hook".text = ''
            # cellward host.dns: the resolvers DHCP hands out never reach the
            # host's resolver — its names go through the zone.
            skip_hooks="$skip_hooks resolv.conf"
          '';

          # networkd отдаёт resolved резолверы каждого .network сам, и общего
          # «не брать» в networkd.conf нет — только в каждой сети.
          assertions = [
            {
              assertion = !(config.systemd.network.enable && config.services.resolved.enable) || networkdLeaks == { };
              message = "services.cellward.system.host.dns: systemd-networkd would hand resolved the resolvers of ${lib.concatStringsSep ", " (lib.attrNames networkdLeaks)}, and the host's names would go to them around the zone. For each: dhcpV4Config.UseDNS = false; dhcpV6Config.UseDNS = false; ipv6AcceptRAConfig.UseDNS = false; and no networkConfig.DNS.";
            }
          ];
          warnings = lib.optional ((cfg.zones.${cfg.host.dns}.kind or "plain") != "plain") "services.cellward.system.host.dns = \"${cfg.host.dns}\" is a VPN zone: the host's names go through it, and so would the name of its own endpoint — give the endpoint as an address, or the zone never comes up.";
        }
      ))

      # --- ВЫКЛЮЧАТЕЛЬ (docs/SYSTEM.md §9a) ---
      # vpn-zones целиком выключаются и включаются без пересборки и без
      # интернета — и без нашей программы: systemd, nft и coreutils. Метка
      # переживает перезагрузку.
      (
        let
          attached = map (u: "${u}.service") (lib.attrNames attachedServices);
          autoStarted = map (n: "${holderUnit n}.service") (
            lib.attrNames (lib.filterAttrs (_: z: z.autoStart) cfg.zones)
          );
          nft = "${pkgs.nftables}/bin/nft";
          # Выключение: дополнений уже нет, службы встают в сети хоста.
          detach = lib.optional (attached != [ ]) "-${systemctl} try-restart ${lib.concatStringsSep " " attached}";
          # Включение — наоборот, и порядок здесь важен. Служба с `BindsTo`
          # на неподнятую зону будет остановлена systemd сразу при
          # daemon-reload и сама не вернётся; а `try-restart` зону не
          # поднимет — он не тянет зависимостей. Поэтому: запомнить, какие
          # службы работают, поднять их зоны, перечитать юниты, перезапустить.
          reattach = pkgs.writeShellScript "vpn-zones-reattach" ''
            active=
            for pair in ${
              lib.escapeShellArgs (
                lib.mapAttrsToList (u: s: "${u}.service:${holderUnit s.zone}.service") attachedServices
              )
            }; do
              u=''${pair%%:*}
              if ${systemctl} -q is-active "$u"; then
                active="$active $u"
                ${systemctl} start "''${pair#*:}" || true
              fi
            done
            ${systemctl} daemon-reload
            for u in $active; do
              ${systemctl} restart "$u" || true
            done
          '';
        in
        {
          systemd.services.vpn-zones-off = {
            description = "cellward: off — everything back on the host's network until vpn-zones-on";
            serviceConfig = {
              Type = "oneshot";
              ExecStart = [
                "${pkgs.coreutils}/bin/touch ${offFlag}"
                "-${nft} delete table inet vpnzones_egress"
                # Генератор видит метку и больше не привязывает службы…
                "${systemctl} daemon-reload"
              ]
              # …и они встают заново уже в сети хоста;
              ++ detach
              ++ [
                # зоны — последними: привязанные к ним службы уже отвязаны.
                "-${systemctl} stop vpn-zones-egress.service"
                "-${systemctl} stop vpn-zone-system@*.service vpn-zone-system-ns@*.service"
              ];
            };
          };
          systemd.services.vpn-zones-on = {
            description = "cellward: on again";
            serviceConfig = {
              Type = "oneshot";
              # Политика — первой: хост закрывается как можно раньше. Не
              # загрузилась — зоны всё равно возвращаются, но служба падает и
              # говорит об этом: «включено» без политики — не «включено»
              # (ревью 2026-09-25).
              ExecStart = pkgs.writeShellScript "vpn-zones-on" ''
                ${pkgs.coreutils}/bin/rm -f ${offFlag}
                policy=0
                ${systemctl} start vpn-zones-egress.service || policy=1
                ${lib.optionalString (autoStarted != [ ]) "${systemctl} start ${lib.concatStringsSep " " autoStarted} || true"}
                ${reattach} || true
                if [ "$policy" != 0 ]; then
                  echo "cellward on, but the egress policy did not load — the host keeps its own network" >&2
                  exit 1
                fi
              '';
            };
          };
          environment.systemPackages = [
            (pkgs.writeShellScriptBin "vpn-zones-off" ''
              exec ${systemctl} start vpn-zones-off.service
            '')
            (pkgs.writeShellScriptBin "vpn-zones-on" ''
              exec ${systemctl} start vpn-zones-on.service
            '')
          ];
          security.polkit.enable = lib.mkIf (cfg.switchGroup != null) true;
          security.polkit.extraConfig = lib.mkIf (cfg.switchGroup != null) ''
            // Is the process in a login session's own scope (session-N.scope)?
            function inSessionScope(pid) {
              try {
                polkit.spawn(["${pkgs.gnugrep}/bin/grep", "-qE",
                  "^0::/user\\.slice/user-[0-9]+\\.slice/session-[0-9]+\\.scope$",
                  "/proc/" + pid + "/cgroup"]);
                return true;
              } catch (error) {
                return false;
              }
            }
            polkit.addRule(function(action, subject) {
              if (action.id == "org.freedesktop.systemd1.manage-units" &&
                  ["vpn-zones-off.service", "vpn-zones-on.service"].indexOf(action.lookup("unit")) >= 0 &&
                  action.lookup("verb") == "start" &&
                  subject.isInGroup("${cfg.switchGroup}")) {
                // Off — with a password, at the machine too (owner,
                // 2026-09-25): a zone's program able to write the home puts a
                // line into the shell's startup, and the next login at the
                // seat switches the protection off by itself. On — without
                // one from the person at the machine: the session in front,
                // local and active, AND the asking process really in that
                // session's scope (polkit takes a process outside any session
                // for the user's display session, review 2026-09-25). From
                // anywhere else, a password either way.
                if (action.lookup("unit") == "vpn-zones-off.service") {
                  return polkit.Result.AUTH_SELF_KEEP;
                }
                return (subject.local && subject.active && inSessionScope(subject.pid))
                  ? polkit.Result.YES
                  : polkit.Result.AUTH_SELF_KEEP;
              }
            });
          '';
        }
      )

      # --- ПУЛЬТ TTY (docs/SYSTEM.md §7a) ---
      # Вход на текстовой консоли: сразу меню с сетью. Решает, показываться ли,
      # сама программа (только VT, только вне зоны, только пользователям зоны),
      # а при любой ошибке уступает обычной оболочке — запереть снаружи пульт
      # не может.
      (lib.mkIf cfg.console.enable {
        assertions = [
          {
            assertion = cfg.zones ? ${cfg.console.zone} && cfg.zones.${cfg.console.zone}.users != [ ];
            message = "services.cellward.system.console.zone = \"${cfg.console.zone}\" has to be a declared zone with users.";
          }
          {
            assertion =
              cfg.console.fallback == null
              || (cfg.zones ? ${cfg.console.fallback} && cfg.zones.${cfg.console.fallback}.kind == "plain");
            message = "services.cellward.system.console.fallback has to be a declared plain zone.";
          }
        ];
        environment.etc."vpn-zones/console".text =
          "zone=${cfg.console.zone}\n"
          + lib.optionalString (cfg.console.fallback != null) "fallback=${cfg.console.fallback}\n"
          + lib.optionalString (cfg.console.admin != null) (
            "admin=${cfg.console.admin.command}\nadmin-label=${cfg.console.admin.label}\n"
          );
        environment.systemPackages = [
          (pkgs.writeShellScriptBin "vpn-zone-console" ''
            exec ${core} console "$@"
          '')
        ];
        # Один раз на вход (оболочка в зоне — тоже оболочка входа) и только в
        # интерактивной: display manager запускает сеанс через `bash -l -c …`,
        # часто прямо на VT, и встать перед композитором пульт не должен.
        environment.loginShellInit = ''
          case $- in
            *i*)
              if [ -z "''${VPN_ZONE_CONSOLE-}" ]; then
                export VPN_ZONE_CONSOLE=1
                ${core} console --login
              fi
              ;;
          esac
        '';
      })

      # --- ХОСТ БЕЗ СЕТИ (этап 5, docs/SYSTEM.md §9) ---
      # Своя таблица nftables и свой юнит: откат поколения снимает политику
      # вместе со всем остальным. Признак — владелец сокета, а не cgroup:
      # наборы cgroup пустеют при каждой перезагрузке фаервола.
      (lib.mkIf cfg.egress.enable (
        let
          e = cfg.egress;
          nft = "${pkgs.nftables}/bin/nft";
          # Запрет — из файла, собранного вместе с системой, и грузит его сам
          # nft. Наша программа только ДОПИСЫВАЕТ разрешения (выходы
          # пользовательских зон, названных людей): упадёт она — хост станет
          # закрытее, а не открытым. `nixbld` известен при сборке — он в файле.
          nixbldInFile = builtins.elem "nixbld" e.allowGroups;
          strict = e.mode == "strict";
          # Префиксы проверяет сама программа при сборке: кривой не соберётся,
          # а не оставит хост без политики при загрузке.
          rules = pkgs.runCommand "vpn-zones-egress.nft" { } (
            "${core} egress print"
            + lib.optionalString (e.mode == "enforce") " --enforce"
            + lib.optionalString strict (
              " --strict" + lib.concatMapStrings (p: " --local ${lib.escapeShellArg p}") e.localNetworks
            )
            + lib.optionalString nixbldInFile " --gid ${toString config.ids.gids.nixbld}"
            + " > $out"
          );
          allow = lib.concatStringsSep " " (
            [ "${core} egress allow --nft ${nft}" ]
            # strict: системные пользователи больше не выходят все подряд, а
            # pasta простых зон — это выход «напрямую» для всего в них.
            ++ lib.optional strict "--user ${plainUser}"
            ++ map (u: "--user ${lib.escapeShellArg u}") e.allowUsers
            ++ map (g: "--group ${lib.escapeShellArg g}") (lib.remove "nixbld" e.allowGroups)
          );
          # «-»: разрешения не добавились — политика стоит строже, а не падает.
          apply = [
            "${nft} -f ${rules}"
            "-${allow}"
          ];
          # Фаервол NixOS, стирающий ВСЕ таблицы при перезагрузке, стёр бы и
          # нашу — тогда политика перечитывается вслед за ним.
          flushes = config.networking.nftables.enable && config.networking.nftables.flushRuleset;
        in
        {
          # Без сети у демона система не соберёт следующую версию себя —
          # такую конфигурацию не собрать вовсе, а не предупредить о ней.
          assertions = [
            {
              assertion = !strict || cfg.host.nix != null;
              message = "services.cellward.system.egress.mode = \"strict\" closes the network to the Nix daemon: substitutes and the builds that fetch would fail, and the next rebuild with them. Put it into a zone: services.cellward.system.host.nix = \"<zone>\" (a plain zone is directly).";
            }
          ];
          warnings =
            lib.optional (
              strict && cfg.host.time == null && config.services.timesyncd.enable
            ) "services.cellward.system.egress.mode = \"strict\" closes the network to systemd-timesyncd: the clock will drift. Put it into a zone: services.cellward.system.host.time = \"<zone>\" (a plain zone is directly).";

          # Проверка связности NetworkManager (root, в интернет) под strict
          # не пройдёт, и NM сообщит «ограниченное подключение» всем, кто
          # его спрашивает, хотя в зонах сеть есть. Выключенная — не мешает.
          networking.networkmanager.settings.connectivity.enabled = lib.mkIf (
            strict && config.networking.networkmanager.enable
          ) (lib.mkDefault false);

          systemd.services.vpn-zones-egress = {
            description = "cellward: the host egress policy (${e.mode})";
            # Путь спасения без единого нашего бинарника: `vpnzones.egress=off`
            # в строке ядра (в меню загрузки — `e`) — и политика не поднимается.
            unitConfig.ConditionKernelCommandLine = [
              "!vpnzones.egress=off"
              "!vpnzones=off"
            ];
            unitConfig.ConditionPathExists = "!${offFlag}";
            wantedBy = [ "multi-user.target" ];
            before = [ "network-pre.target" ];
            wants = [ "network-pre.target" ];
            after = [ "nftables.service" ];
            partOf = lib.optional flushes "nftables.service";
            unitConfig.ReloadPropagatedFrom = lib.optional flushes "nftables.service";
            reloadIfChanged = true;
            serviceConfig = {
              Type = "oneshot";
              RemainAfterExit = true;
              ExecStart = apply;
              ExecReload = apply;
              # `delete`, не `destroy`: тот требует nft 1.0.8 и ядра 6.3.
              ExecStop = "-${nft} delete table inet vpnzones_egress";
            };
          };

          # Аварийный ключ: таблица остаётся, ограничение снимается на
          # e.emergency.minutes и возвращается само — и по истечении, и при
          # остановке юнита.
          systemd.services.vpn-zones-egress-open = {
            description = "cellward: the host egress policy lifted for ${toString e.emergency.minutes} minutes";
            serviceConfig = {
              Type = "simple";
              # Сам nft, без vpn-zone-core: ключ должен повернуться и тогда,
              # когда сломано всё наше.
              ExecStartPre = "-${nft} delete table inet vpnzones_egress";
              ExecStart = "${pkgs.coreutils}/bin/sleep ${toString (e.emergency.minutes * 60)}";
              ExecStopPost = apply;
            };
          };

          # Без polkit правило ниже никого не пустит, а в NixOS он выключен по
          # умолчанию. Явный `security.polkit.enable = false` здесь даст
          # конфликт определений — это и есть выбор: ключ группе или без polkit
          # (emergency.group = null, ключ только у root).
          security.polkit.enable = lib.mkIf (e.emergency.group != null) true;
          security.polkit.extraConfig = lib.mkIf (e.emergency.group != null) ''
            // Is the process in a login session's own scope (session-N.scope)?
            function inSessionScopeKey(pid) {
              try {
                polkit.spawn(["${pkgs.gnugrep}/bin/grep", "-qE",
                  "^0::/user\\.slice/user-[0-9]+\\.slice/session-[0-9]+\\.scope$",
                  "/proc/" + pid + "/cgroup"]);
                return true;
              } catch (error) {
                return false;
              }
            }
            polkit.addRule(function(action, subject) {
              if (action.id == "org.freedesktop.systemd1.manage-units" &&
                  action.lookup("unit") == "vpn-zones-egress-open.service" &&
                  (action.lookup("verb") == "start" || action.lookup("verb") == "stop") &&
                  subject.isInGroup("${e.emergency.group}")) {
                // Turned — with a password, at the machine too, as the
                // switch's "off" above; the TTY console asks for it. Turned
                // back, which only closes the host again: without one at the
                // machine itself.
                if (action.lookup("verb") == "start") {
                  return polkit.Result.AUTH_SELF_KEEP;
                }
                return (subject.local && subject.active && inSessionScopeKey(subject.pid))
                  ? polkit.Result.YES
                  : polkit.Result.AUTH_SELF_KEEP;
              }
            });
          '';
        }
      ))

      # --- NIXOS-КОНТЕЙНЕРЫ В ЗОНЕ (этап 3) ---
      {
        # Сеть — НЕ через containers.<c>.networkNamespace: nspawn входит в
        # чужое сетевое пространство уже из нового user namespace контейнера,
        # а пространство зоны принадлежит user namespace хоста — «Failed to
        # join network namespace: Operation not permitted» при
        # privateUsers = "pick" (проверено в tests/vm-system.nix). Поэтому в
        # зону входит сам systemd, до запуска nspawn (NetworkNamespacePath у
        # container@<c> ниже), а nspawn без сетевых флагов делит сеть, в
        # которой запущен, — сеть зоны. Свой user namespace контейнер получает
        # как обычно, и прав над сетью зоны у его root нет.
        containers = lib.mapAttrs (_c: a: {
          privateUsers = lib.mkDefault "pick";
          extraFlags = [
            # Стартовый скрипт nixpkgs копирует resolv.conf хоста в корень
            # каждого контейнера; поверх него — файл зоны, и nspawn его не трогает.
            "--resolv-conf=off"
            "--bind-ro=${resolvPath a.zone}:/etc/resolv.conf"
          ]
          # Сокет nix-daemon ХОСТА nixpkgs монтирует в каждый контейнер, и любой
          # пользователь там может попросить демон собрать fixed-output
          # деривацию — то есть скачать что угодно из сети хоста, мимо туннеля.
          ++ lib.optional (
            config.nix.enable && (config.nix.daemon.enable or true)
          ) "--inaccessible=/nix/var/nix/daemon-socket";
        }) cfg.containers;

        systemd.services = lib.mapAttrs' (
          c: a:
          lib.nameValuePair "container@${c}" (
            consumerDeps a.zone
            // {
              serviceConfig.NetworkNamespacePath = netnsPath a.zone;
            }
          )
        ) cfg.containers;
      }
    ]
  );
}
