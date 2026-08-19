#!/usr/bin/env python3
"""Генератор .desktop для VPN-зон. Два режима, переключаются `vpn-zone mode`.

РЕЖИМ picker (по умолчанию) — то, ради чего это переписывалось.
Ярлык приложения остаётся ОДИН, но перехватывается: вместо самой программы он
запускает пикер, который спрашивает «в какой сети запускать?» и уже сам зовёт
программу. Лаунчер не разрастается, а выбор сети делается в момент запуска.
Перехват — обычный XDG-приём: файл с тем же именем в ~/.local/share/applications
перекрывает системный. Оригиналы в /nix/store не трогаются вовсе, откат — просто
удалить наши файлы (`vpn-zone mode off`).

РЕЖИМ per-zone — прежнее поведение: на каждую зону свой ярлык «Firefox (nl)».
Полезно, если хочется запускать в конкретную зону одним кликом без диалога.
Режим both делает и то, и другое.

ЗАЩИТА ОТ САМОПОЕДАНИЯ (в обоих режимах):
  • файлы с ключом X-VPNZone на вход не берутся;
  • в режиме per-zone клоны ещё и по префиксу имени отсеиваются;
  • чужие файлы в ~/.local/share/applications (симлинки home-manager, ручные
    ярлыки) не перезаписываются НИКОГДА — только наши собственные, помеченные
    маркером; иначе первый же sync затёр бы ярлыки, которые кладёт Nix.
"""

import os
import re
import sys
from pathlib import Path

PREFIX = "vpn-zone-"
MARK = "X-VPNZone"

# Что переносим в клон в режиме per-zone. MimeType здесь НЕТ намеренно: иначе
# клоны начнут перехватывать ассоциации файлов, и «открыть картинку» однажды
# молча уедет в зону с VPN. В режиме picker наоборот — там ярлык один и он
# ОБЯЗАН сохранить ассоциации, иначе программа перестанет быть обработчиком.
CLONE_KEYS = {
    "Icon", "Terminal", "Categories", "Keywords",
    "StartupNotify", "StartupWMClass", "Path",
}
LOCALIZED_LABEL = re.compile(r"^(Name|GenericName|Comment)(\[[^\]]+\])?$")
FIELD_CODES = re.compile(r"%[fFuUdDnNickvm]")


def parse_desktop(path):
    """Читает .desktop целиком: [(имя группы, {ключ: значение}), ...]."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    groups, current = [], None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            current = (s[1:-1], {})
            groups.append(current)
            continue
        if current is None or not s or s.startswith("#") or "=" not in s:
            continue
        key, value = s.split("=", 1)
        current[1][key.strip()] = value.strip()
    return groups


def entry_of(groups):
    for name, data in groups:
        if name == "Desktop Entry":
            return data
    return {}


def is_candidate(path, entry):
    if path.name.startswith(PREFIX):
        return False
    if any(k == MARK or k.startswith(MARK + "[") for k in entry):
        return False
    if entry.get("Type", "Application") != "Application":
        return False
    if entry.get("NoDisplay", "false").lower() == "true":
        return False
    if entry.get("Hidden", "false").lower() == "true":
        return False
    return bool(entry.get("Exec"))


def source_dirs(home):
    dirs = [
        Path(home) / ".local/share/applications",
        Path(f"/etc/profiles/per-user/{os.environ.get('USER', '')}/share/applications"),
        Path("/run/current-system/sw/share/applications"),
    ]
    for d in os.environ.get("XDG_DATA_DIRS", "").split(":"):
        if d:
            dirs.append(Path(d) / "applications")
    seen, result = set(), []
    for d in dirs:
        if str(d) not in seen and d.is_dir():
            seen.add(str(d))
            result.append(d)
    return result


def collect_apps(home, out_dir):
    """{имя файла: (группы, был ли найден в нашем выходном каталоге)}."""
    apps = {}
    for d in source_dirs(home):
        own_dir = d.resolve() == out_dir.resolve()
        for path in sorted(d.glob("*.desktop")):
            if path.name in apps:
                continue
            groups = parse_desktop(path)
            if groups and is_candidate(path, entry_of(groups)):
                apps[path.name] = (groups, own_dir)
    return apps


def ours(path):
    """Наш ли это файл — можно ли его безопасно перезаписать/удалить."""
    if path.is_symlink() or not path.is_file():
        return False
    try:
        return MARK + "=" in path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False


def occupied(path):
    """Существует ли что-то по этому пути — включая БИТЫЕ симлинки.

    exists() на симлинк, указывающий в никуда, возвращает False, и без этой
    проверки sync попытался бы записать файл ПО симлинку — то есть в чужую цель
    (в случае home-manager это /nix/store, read-only, и весь проход падал бы с
    OSError). Проверено: именно так и произошло.
    """
    return path.exists() or path.is_symlink()


def write_if_changed(target, content):
    """Пишет только при изменении; возвращает 1, если файл был записан.

    Сравнение обязательно: иначе path-юнит, следящий за каталогом, будил бы
    sync, тот переписывал бы файлы, и цикл не заканчивался бы никогда.
    """
    try:
        if target.exists() and target.read_text(encoding="utf-8") == content:
            return 0
        target.write_text(content, encoding="utf-8")
        return 1
    except OSError as e:
        print(f"пропускаю {target.name}: {e}", file=sys.stderr)
        return 0


def render_clone(entry, zone, runner):
    """per-zone: «Firefox (nl)» — отдельный ярлык на зону."""
    exec_line = FIELD_CODES.sub("", entry["Exec"]).strip()
    lines = ["[Desktop Entry]", "Type=Application"]
    for key, value in entry.items():
        m = LOCALIZED_LABEL.match(key)
        if m:
            lines.append(f"{key}={value} ({zone})" if m.group(1) == "Name" else f"{key}={value}")
        elif key in CLONE_KEYS:
            lines.append(f"{key}={value}")
    lines.append(f"Exec={runner} run {zone} -- {exec_line}")
    lines.append(f"{MARK}={zone}")
    return "\n".join(lines) + "\n"


def render_picker(groups, picker, app_id, app_key):
    """picker: тот же ярлык, но Exec ведёт в диалог выбора сети.

    app_key — идентификатор ярлыка (имя файла без .desktop). Он передаётся пикеру
    как --id и служит ключом памяти «какая сеть и какой контейнер выбраны для
    этой программы». Раньше ключ вычислялся из первого слова команды, и для
    ярлыков вида `Exec=env DESKTOPINTEGRATION=1 AyuGram` получался «env» — то
    есть все такие программы делили одну память, а в списке сбросов виднелось
    загадочное «env».

    В Exec НЕ ДОЛЖНО БЫТЬ КАВЫЧЕК, и это не вкусовщина. Сначала сюда честно
    подставлялось название программы («Zen Browser») в кавычках, по правилам
    desktop-спецификации. Но Telegram (и не он один) разбирает Exec наивно, по
    пробелам, кавычки не снимая: аргумент разваливался на `Zen` и `Browser"`,
    пикер принимал мусор за команду, и запуск падал с «невозможно выполнить
    Browser"». Поэтому в командной строке остаются только слова без пробелов, а
    человекочитаемое имя пикер берёт из файла меток, который пишется здесь же.
    """
    out = []
    for name, data in groups:
        if name != "Desktop Entry" and not name.startswith("Desktop Action "):
            continue
        out.append(f"[{name}]")
        label = data.get("Name", app_id)
        for key, value in data.items():
            if key in ("Exec", "DBusActivatable", "TryExec") or key == MARK:
                continue
            out.append(f"{key}={value}")
        if data.get("Exec"):
            # Коды полей (%U, %f) сохраняем: ярлык остаётся обработчиком файлов,
            # и путь долетит до программы через пикер как обычный аргумент.
            # ВАЖНО: app_key, а не key — последняя внутри цикла по data.items(),
            # и подстановка её сюда дала бы случайный ключ .desktop вместо id.
            out.append(f"Exec={picker} --id {sanitize(app_key)} -- {data['Exec']}")
        # Без этого лаунчер активирует программу через dbus мимо Exec — и весь
        # перехват был бы бесполезен.
        out.append("DBusActivatable=false")
        if name == "Desktop Entry":
            out.append(f"{MARK}=picker")
        out.append("")
    return "\n".join(out)


def sanitize(s):
    """Ключ без пробелов и кавычек — чтобы Exec разбирался кем угодно."""
    return re.sub(r"[^A-Za-z0-9_.-]", "_", s)


def write_label(state_dir, key, label):
    """Человекочитаемое имя рядом с ключом: диалоги и списки сбросов
    показывают «Zen Browser», хотя в командной строке остаётся только id."""
    try:
        d = Path(state_dir) / ".labels"
        d.mkdir(parents=True, exist_ok=True)
        (d / sanitize(key)).write_text(label, encoding="utf-8")
    except OSError:
        pass


def shquote(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def main():
    state_dir, home, runner, picker = (Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4])
    out_dir = Path(home) / ".local/share/applications"
    out_dir.mkdir(parents=True, exist_ok=True)

    mode_file = Path(home) / ".config/vpn-zones/mode"
    mode = mode_file.read_text(encoding="utf-8").strip() if mode_file.is_file() else "picker"
    if mode not in ("picker", "per-zone", "both", "off"):
        mode = "picker"

    zones = sorted(
        p.name for p in state_dir.glob("*")
        if (p / "config.conf").is_file() and not p.name.startswith(".")
    ) if state_dir.is_dir() else []

    apps = collect_apps(home, out_dir) if mode != "off" else {}
    wanted, written = set(), 0

    for name, (groups, own_dir) in apps.items():
        entry = entry_of(groups)

        # picker перехватывает ярлык под его собственным именем — значит трогать
        # можно только те, что пришли из системных каталогов. Файлы, которые уже
        # лежат в ~/.local/share/applications (наши служебные, ярлыки от
        # home-manager), оставляем как есть.
        if mode in ("picker", "both") and not own_dir:
            target = out_dir / name
            if not occupied(target) or ours(target):
                wanted.add(target.name)
                app_key = name[:-len(".desktop")] if name.endswith(".desktop") else name
                write_label(state_dir, app_key, entry.get("Name", app_key))
                written += write_if_changed(
                    target, render_picker(groups, picker, entry.get("Name", name), app_key)
                )

        if mode in ("per-zone", "both"):
            for zone in zones:
                target = out_dir / f"{PREFIX}{zone}-{name}"
                if occupied(target) and not ours(target):
                    continue
                wanted.add(target.name)
                written += write_if_changed(target, render_clone(entry, zone, runner))

    # Уборка: наши файлы, которые больше не нужны (сменился режим, удалена зона,
    # программа исчезла). Чужое не трогаем — ours() проверяет и маркер, и то, что
    # это не симлинк.
    removed = 0
    for path in out_dir.glob("*.desktop"):
        # Наши собственные пункты меню («Добавить зону», «Сбросить сети») кладёт
        # home-manager симлинками — ours() их и так не тронет, но перечисляем
        # явно, чтобы намерение было видно.
        own_entries = (
            f"{PREFIX}add.desktop",
            f"{PREFIX}remove.desktop",
            f"{PREFIX}forget.desktop",
        )
        if path.name in own_entries or path.name in wanted:
            continue
        if ours(path):
            path.unlink()
            removed += 1

    print(
        f"режим {mode}: ярлыков {len(wanted)} (обновлено {written}, удалено {removed})"
        f"; зон: {', '.join(zones) or 'нет'}"
    )


if __name__ == "__main__":
    main()
