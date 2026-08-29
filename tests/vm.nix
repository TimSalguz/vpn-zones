# NixOS VM test: boots a real machine with the vpn-zones home-manager module
# and exercises exactly the paths the CI smoke test cannot reach — a runner
# has no systemd user session, so `vpn-zone up/down` (the vpn-zone@ template
# unit), the unit autostart inside `vpn-zone run`, and the picker's offline
# branch have no coverage there. Here they do, plus the same hermeticity
# asserts as the smoke test, checked through the systemd path this time.
#
# A second VM acts as a REAL WireGuard peer on the test's private VLAN, so
# the handshake, the traffic, the DNS= path and `vpn-zone check`'s "tunnel
# alive" branch are exercised for real — with a tcpdump on the client's
# physical interface asserting that nothing but the tunnel's own UDP ever
# leaves towards the server (a first cut of the ROADMAP leak tests). Keys
# are generated at runtime inside the VMs: no real VPN config is involved,
# and the test needs no internet and nothing from the host.
#
# The host stays untouched: everything happens inside a qemu VM whose state
# dirs are the VM's own; the only host side effect is /nix/store growth.
# Works without /dev/kvm too — qemu falls back to TCG emulation (an order of
# magnitude slower, but correct).
#
# Run:
#   nix-build tests/vm.nix -A driver && ./result/bin/nixos-test-driver
# Poke at the VM by hand (python REPL; `machine.shell_interact()`):
#   nix-build tests/vm.nix -A driverInteractive && ./result/bin/nixos-test-driver
#
# Unlike the smoke test, the second-echelon assert is STRICT here: the VM
# kernel loads nf_tables up front, so the "runner kernel has no nf_tables"
# degradation branch must not fire — rules are either present or it is a bug.
{
  system ? builtins.currentSystem,
}:

let
  pins = import ./pins.nix;
  pkgs = import pins.nixpkgs {
    inherit system;
    config = { };
    overlays = [ ];
  };

  test = pkgs.testers.runNixOSTest {
    name = "vpn-zones-vm";

    nodes.machine =
      { pkgs, ... }:
      {
        imports = [ "${pins.home-manager}/nixos" ];

        users.users.alice = {
          isNormalUser = true;
          uid = 1000;
          # The zone holder maps its in-namespace root from this range via the
          # setuid newuidmap — the same prerequisite the README states for a
          # real machine.
          subUidRanges = [
            {
              startUid = 100000;
              count = 65536;
            }
          ];
          subGidRanges = [
            {
              startGid = 100000;
              count = 65536;
            }
          ];
          # A user manager without a login session: `vpn-zone up` talks to
          # `systemctl --user`, and nobody logs into a test VM.
          linger = true;
        };

        # zsh, like on a real desktop: without it /share/zsh is not linked into
        # the per-user profile and the completion assert below would test
        # nothing.
        programs.zsh.enable = true;

        home-manager.useGlobalPkgs = true;
        # Per-user profile at /etc/profiles/per-user/alice — the layout the
        # module sees on a real NixOS machine, and the path its tools manifest
        # bakes into `runner`/`picker` (home.profileDirectory).
        home-manager.useUserPackages = true;
        home-manager.users.alice = {
          imports = [ ../module ];
          programs.vpn-zones.enable = true;
          home.stateVersion = "26.05";
        };

        boot.kernelModules = [
          # No amneziawg module in the VM (yet): the holder falls back to
          # kernel WireGuard, same as CI. Modules cannot autoload from an
          # unprivileged userns, so everything a zone needs is loaded up front.
          "wireguard"
          # pasta opens /dev/net/tun.
          "tun"
          # Second echelon; with the module loaded the nft asserts are strict.
          "nf_tables"
        ];

        environment.systemPackages = [
          # `wg genkey` for the synthetic config the test writes.
          pkgs.wireguard-tools
          # To READ rulesets from inside the zone's namespaces. The zone itself
          # gets its own nft path via the unit's ExecStart flags.
          pkgs.nftables
          # For the real-tunnel part: TCP client inside the zone, DNS client,
          # and the leak capture on the uplink interface.
          pkgs.socat
          pkgs.dnsutils
          pkgs.tcpdump
        ];

        virtualisation.cores = 4;
        virtualisation.memorySize = 2048;
      };

    # A real WireGuard peer for the zone to talk to, on the test VLAN between
    # the two VMs (a virtual hub private to this test — the host is not
    # involved and neither VM has internet). Keys are generated at runtime
    # inside the VMs, so no VPN config ever exists outside the test.
    nodes.server =
      { pkgs, ... }:
      {
        boot.kernelModules = [ "wireguard" ];
        environment.systemPackages = [
          pkgs.wireguard-tools
          # The service behind the tunnel: a TCP responder that reports the
          # peer address it saw, and a DNS server for the DNS= path.
          pkgs.socat
          pkgs.dnsmasq
        ];
        networking.firewall.allowedUDPPorts = [ 51820 ];
        # Services listen on the tunnel address only; the firewall must not
        # get in their way there.
        networking.firewall.trustedInterfaces = [ "wg0" ];
      };

    testScript = ''
      import shlex

      STATE = "/home/alice/.local/state/vpn-zones"

      def alice(cmd):
          """Run a command as alice with her user manager reachable."""
          return machine.succeed(
              "su -l alice -c "
              + shlex.quote("export XDG_RUNTIME_DIR=/run/user/1000; " + cmd)
          )

      def in_zone(pid, cmd):
          """Enter the app namespace the way `vpn-zone run` does."""
          return alice(f"nsenter --preserve-credentials -U -n -m -t {pid} -- {cmd}")

      def in_zone_root(pid, cmd):
          """uid 0 inside the zone's userns: nfnetlink wants CAP_NET_ADMIN even
          for reading, and a plain user's capabilities die on execve
          (docs/GOTCHAS.md §1)."""
          return alice(f"nsenter -U -n -m -t {pid} -- {cmd}")

      # Both VMs boot in parallel; the server is only needed much later.
      start_all()

      machine.wait_for_unit("multi-user.target")
      # The module arrives through home-manager's system activation unit;
      # nothing exists in alice's profile before it finishes.
      machine.wait_for_unit("home-manager-alice.service")
      machine.wait_for_unit("user@1000.service")

      with subtest("module delivered: CLI in PATH, template unit installed"):
          alice("command -v vpn-zone")
          alice("systemctl --user cat vpn-zone@.service > /dev/null")
          alice("systemctl --user cat vpn-zone-desktop-sync.timer > /dev/null")
          machine.succeed(
              "test -f /etc/profiles/per-user/alice"
              "/share/zsh/site-functions/_vpn-zone"
          )

      with subtest("vpn-zone add: synthetic config (wg genkey, TEST-NET endpoint)"):
          alice(
              "priv=$(wg genkey); peer=$(wg genkey | wg pubkey); "
              "printf '[Interface]\\nPrivateKey = %s\\nAddress = 10.99.0.2/32\\n\\n"
              "[Peer]\\nPublicKey = %s\\nAllowedIPs = 0.0.0.0/0\\n"
              "Endpoint = 192.0.2.1:51820\\n' \"$priv\" \"$peer\" > /tmp/vmsmoke.conf"
          )
          alice("vpn-zone add vmsmoke /tmp/vmsmoke.conf")
          machine.succeed(f"test -f {STATE}/vmsmoke/config.conf")

      with subtest("vpn-zone up: starts the vpn-zone@ unit and waits for ready"):
          alice("vpn-zone up vmsmoke")
          alice("systemctl --user is-active vpn-zone@vmsmoke.service")
          machine.succeed(f"test -f {STATE}/vmsmoke/ready")

      with subtest("tab completion offers the zone where a zone is expected"):
          out = alice("vpn-zone _complete -- vpn-zone up \"\" 3")
          assert "vmsmoke" in out.split(), out

      zpid = machine.succeed(f"cat {STATE}/vmsmoke/zone.pid").strip()
      upid = machine.succeed(f"cat {STATE}/vmsmoke/uplink.pid").strip()
      assert zpid != upid, "zone.pid and uplink.pid are one namespace, must be two"

      # The main hermeticity assert (docs/LEAK-MODEL.md): everything else —
      # routes, IPv6, DNS — is a consequence of "nothing but lo and the tunnel
      # exists in the app namespace".
      with subtest("hermeticity: exactly lo and awg0 in the app-ns"):
          links = in_zone(zpid, "ip -o link show")
          assert len(links.strip().splitlines()) == 2, f"extra links in app-ns: {links}"
          assert ": lo:" in links, links
          assert ": awg0" in links, links

      with subtest("v4 default route through the tunnel"):
          out = in_zone(zpid, "ip -4 route show default")
          assert "dev awg0" in out, out

      with subtest("no IPv6 path out (config has no v6)"):
          out = in_zone(zpid, "sh -c 'ip -6 route show default 2>/dev/null || true'")
          assert out.strip() == "" or out.strip().startswith("unreachable"), out

      with subtest("zone DNS defaults to 1.1.1.1 (config has no DNS=)"):
          out = in_zone(zpid, "cat /etc/resolv.conf")
          assert "nameserver 1.1.1.1" in out, out

      with subtest("route to the endpoint goes INTO the tunnel (no loop by design)"):
          out = in_zone(zpid, "ip route get 192.0.2.1")
          assert "dev awg0" in out, out

      with subtest("second echelon, app-ns: output drops everything but awg0"):
          rules = in_zone_root(zpid, "nft list ruleset")
          for pat in ["chain output", "policy drop", 'oifname "awg0" accept']:
              assert pat in rules, f"app-ns ruleset lacks {pat!r}:\n{rules}"

      with subtest("uplink: pasta interface, default route, awg0 moved away"):
          links = in_zone(upid, "ip -o link show")
          assert ": hostif" in links, f"no pasta interface in uplink-ns: {links}"
          assert "awg0" not in links, f"awg0 stayed in uplink-ns: {links}"
          out = in_zone(upid, "ip -4 route show default")
          assert out.strip(), "no default route in uplink-ns — pasta gave no way out"

      with subtest("second echelon, uplink: only tunnel transport may leave"):
          rules = in_zone_root(upid, "nft list ruleset")
          for pat in [
              "chain output",
              "policy drop",
              "daddr 192.0.2.1 udp dport 51820 accept",
          ]:
              assert pat in rules, f"uplink ruleset lacks {pat!r}:\n{rules}"

      with subtest("vpn-zone down: unit stops, cgroup takes pasta with it"):
          alice("vpn-zone down vmsmoke")
          status = alice(
              "systemctl --user is-active vpn-zone@vmsmoke.service || true"
          ).strip()
          assert status in ("inactive", "failed"), status
          # The same needle `vpn-zone gc` uses to find an orphaned pasta —
          # except for the [p]: the test driver runs every command through
          # `timeout N bash -c '…'`, and THAT process carries the pattern text
          # in its argv, so a plain pattern matches its own invocation forever.
          # The bracket makes the regex miss its own literal text. On a real
          # failure, dump who the survivor is — uid, parent and cgroup say
          # whether it escaped the unit's cgroup or just ignored the signal.
          try:
              machine.wait_until_fails(
                  f"pgrep -f '[p]asta --netns /proc/{upid}/ns/net'", timeout=120
              )
          except Exception:
              _, dump = machine.execute(
                  "pid=$(pgrep -of '[p]asta --netns'); "
                  "ps -p $pid -o pid,ppid,uid,args; cat /proc/$pid/cgroup"
              )
              raise Exception(f"pasta survived vpn-zone down:\n{dump}")
          out = alice("vpn-zone list")
          assert "vmsmoke — опущена" in out, out

      with subtest("vpn-zone run on a down zone starts the unit by itself"):
          out = alice("vpn-zone run vmsmoke -- ip -o link show")
          assert ": awg0" in out, f"run did not enter the zone: {out}"
          status = alice(
              "systemctl --user is-active vpn-zone@vmsmoke.service || true"
          ).strip()
          assert status == "active", f"run did not leave the unit running: {status}"
          alice("vpn-zone down vmsmoke")

      # The picker branch the smoke test explicitly cannot cover: offline
      # starts vpn-zone@offline through `systemctl --user`. No graphics in the
      # VM either, so the picker must take what would have been highlighted —
      # the remembered last choice. The container axis is pinned to the main
      # profile (`__main__`) so no second dialog is needed.
      with subtest("picker offline branch: zone via systemctl --user, lo-only"):
          alice(f"mkdir -p {STATE}/.last {STATE}/.pinnedprofile")
          alice(f"printf offline > {STATE}/.last/vmpickapp")
          alice(f"printf __main__ > {STATE}/.pinnedprofile/vmpickapp")
          out = alice(
              "env -u WAYLAND_DISPLAY -u DISPLAY "
              "vpn-zone-pick --label VM-picker --id vmpickapp -- ip -o link show"
          )
          lines = [l for l in out.strip().splitlines() if ": " in l]
          assert len(lines) == 1 and ": lo:" in lines[0], f"offline zone not lo-only: {out}"
          status = alice(
              "systemctl --user is-active vpn-zone@offline.service || true"
          ).strip()
          assert status == "active", f"picker did not start the offline unit: {status}"
          alice("vpn-zone down offline")

      # --- The real tunnel: an actual WireGuard peer on the second VM -------
      # Everything above used an unreachable endpoint and checked mechanics;
      # from here on the handshake, the traffic and the DNS are real. This is
      # the first coverage of `vpn-zone check`'s "tunnel alive" branch, and a
      # first cut of the ROADMAP leak tests: while the zone is in active use,
      # the only thing allowed to leave the client machine towards the server
      # is the tunnel's own UDP.
      server.wait_for_unit("multi-user.target")

      with subtest("real tunnel: wireguard peer configured on the server VM"):
          server.succeed(
              "wg genkey > /root/wg.key && wg pubkey < /root/wg.key > /root/wg.pub"
          )
          spub = server.succeed("cat /root/wg.pub").strip()
          cpriv = machine.succeed("wg genkey").strip()
          cpub = machine.succeed(f"printf %s '{cpriv}' | wg pubkey").strip()
          server_ip = server.succeed(
              "ip -4 -o addr show eth1 | head -1 | tr -s ' ' | cut -d' ' -f4 | cut -d/ -f1"
          ).strip()
          assert server_ip, "server has no address on eth1"
          server.succeed(
              "ip link add wg0 type wireguard && "
              "ip addr add 10.99.0.1/24 dev wg0 && "
              "wg set wg0 listen-port 51820 private-key /root/wg.key "
              f"peer '{cpub}' allowed-ips 10.99.0.2/32 && "
              "ip link set wg0 up"
          )
          # The services behind the tunnel, bound to the tunnel address only:
          # a TCP responder that reports the peer address it saw, and DNS.
          server.succeed(
              "systemd-run --unit=hello socat "
              "TCP-LISTEN:8080,bind=10.99.0.1,fork,reuseaddr "
              "'SYSTEM:echo peer=$SOCAT_PEERADDR'"
          )
          server.succeed(
              "systemd-run --unit=dns dnsmasq -k --port=53 --bind-interfaces "
              "--listen-address=10.99.0.1 --no-resolv "
              "--address=/leaktest.internal/10.99.0.9"
          )

      with subtest("vpn-zone add vmreal: config with DNS= and a live endpoint"):
          alice(
              f"printf '[Interface]\\nPrivateKey = {cpriv}\\nAddress = 10.99.0.2/32\\n"
              f"DNS = 10.99.0.1\\n\\n[Peer]\\nPublicKey = {spub}\\n"
              f"AllowedIPs = 0.0.0.0/0\\nEndpoint = {server_ip}:51820\\n' "
              "> /tmp/vmreal.conf"
          )
          alice("vpn-zone add vmreal /tmp/vmreal.conf")
          alice("vpn-zone up vmreal")

      # The capture starts BEFORE any traffic, so the handshake itself is
      # under watch too. `vpn-zone gc`-style precision is not needed: filter
      # by the server address and drop the one flow that is allowed.
      with subtest("leak watch armed on the physical interface"):
          machine.succeed(
              "systemd-run --unit=leakwatch tcpdump -n --immediate-mode -i eth1 "
              f"-w /tmp/leak.pcap 'host {server_ip} and not arp "
              "and not (udp and port 51820)'"
          )
          machine.wait_until_succeeds(
              "journalctl -u leakwatch | grep -q 'listening on eth1'"
          )

      rzpid = machine.succeed(f"cat {STATE}/vmreal/zone.pid").strip()

      with subtest("real traffic: TCP through the tunnel, server sees the tunnel address"):
          out = in_zone(rzpid, "socat -T10 - TCP:10.99.0.1:8080")
          assert "peer=10.99.0.2" in out, f"server saw someone else: {out}"

      with subtest("DNS from the config: resolv.conf points into the tunnel and answers"):
          out = in_zone(rzpid, "cat /etc/resolv.conf")
          assert "nameserver 10.99.0.1" in out, out
          out = in_zone(rzpid, "dig +time=5 +tries=2 +short leaktest.internal @10.99.0.1")
          assert "10.99.0.9" in out, f"DNS through the tunnel failed: {out}"

      with subtest("vpn-zone check reports a live tunnel"):
          # The status mirror refreshes every 5 seconds from inside the zone;
          # give it a couple of cycles after the first handshake.
          machine.wait_until_succeeds(
              "su -l alice -c 'export XDG_RUNTIME_DIR=/run/user/1000; "
              "vpn-zone check vmreal'",
              timeout=60,
          )

      with subtest("the leak capture is empty"):
          machine.succeed("systemctl stop leakwatch")
          count = machine.succeed(
              "tcpdump -nr /tmp/leak.pcap 2>/dev/null | wc -l"
          ).strip()
          if count != "0":
              escaped = machine.succeed("tcpdump -nr /tmp/leak.pcap 2>/dev/null")
              raise AssertionError(f"packets escaped the tunnel:\n{escaped}")
          alice("vpn-zone down vmreal")
    '';
  };
in
{
  inherit test;
  inherit (test) driver driverInteractive;
}
