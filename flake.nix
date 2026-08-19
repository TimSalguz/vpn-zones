{
  description = "VPN-зоны, контейнеры данных и песочницы для запуска программ — из-под пользователя, без root";

  outputs = { self }: {
    homeModules.default = ./module;
    homeManagerModules.default = ./module; # старое имя, для совместимости

    # Проверить, что модуль хотя бы разбирается, можно так:
    #   nix eval --impure --expr '(import <nixpkgs/lib>).evalModules { modules = [ ./module ]; }'
  };
}
