#!/usr/bin/env python3
"""Запуск программы в ПРОФИЛЕ — контейнере данных, независимом от сети.

Вызывается из `vpn-zone run` уже внутри нужного сетевого namespace и внутри
собственного mount namespace (см. vpn-zones.nix). Делает три вещи:

  1. накладывает overlayfs профиля на XDG-каталоги: нижний слой — твой настоящий
     ~/.config и компания (только чтение), верхний — каталог профиля. Программа
     видит свои настройки, но всё, что пишет, уходит в профиль;
  2. отмечает в реестре, что профиль занят такой-то сетью, — чтобы нельзя было
     случайно открыть тот же профиль во второй сети и решить, будто сидишь под
     VPN, когда трафик идёт мимо;
  3. сбрасывает capabilities и запускает программу.

ПОЧЕМУ МОНТИРУЕМ СИСТЕМНЫМ ВЫЗОВОМ, А НЕ `mount`. Утилита mount(8) из util-linux
при запуске не от root пытается сбросить привилегии и падает с «drop permissions
failed» — даже когда права на монтирование есть (CAP_SYS_ADMIN получен от
nsenter --keep-caps). Прямой вызов libc.mount такой проверки не делает.

ПОЧЕМУ СБРАСЫВАЕМ CAPABILITIES. Права нужны ровно на монтирование. Дальше
программа должна работать обычным пользователем: ambient-набор переживает
execve, поэтому без явной очистки Chrome унаследовал бы CAP_SYS_ADMIN внутри
namespace. Хоста это не касается, но зачем.
"""

import ctypes
import os
import shutil
import sys

# XDG-каталоги, которые и делают «профиль». Документы, Загрузки и остальное
# содержимое $HOME намеренно общие: это разделение профилей, а не песочница.
SUBDIRS = [".config", ".local/share", ".cache", ".mozilla", ".pki"]

PR_CAP_AMBIENT = 47
PR_CAP_AMBIENT_CLEAR_ALL = 4


def mount_overlay(libc, lower, upper, work, target):
    opts = f"lowerdir={lower},upperdir={upper},workdir={work},userxattr"
    if libc.mount(b"overlay", target.encode(), b"overlay", 0, opts.encode()) != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"overlay на {target}: {os.strerror(err)}")


def others_alive(regdir, myself):
    """Есть ли в этом контейнере ещё живые программы, кроме нас."""
    if not regdir or not os.path.isdir(regdir):
        return False
    for name in os.listdir(regdir):
        try:
            with open(os.path.join(regdir, name), encoding="utf-8") as f:
                for line in f:
                    pid = line.split(" ", 1)[0]
                    if pid.isdigit() and int(pid) != myself and os.path.isdir(f"/proc/{pid}"):
                        return True
        except OSError:
            continue
    return False


def main():
    if "--" not in sys.argv:
        print("использование: vpn-profile-run <каталог> <зона> <одноразовый 0|1> -- команда",
              file=sys.stderr)
        return 2
    split = sys.argv.index("--")
    profile_dir, zone = sys.argv[1], sys.argv[2]
    ephemeral = len(sys.argv) > 3 and sys.argv[3] == "1"
    regdir = sys.argv[4] if len(sys.argv) > 4 else ""
    cmd = sys.argv[split + 1:]
    if not cmd:
        print("нечего запускать", file=sys.stderr)
        return 2

    home = os.path.expanduser("~")
    libc = ctypes.CDLL("libc.so.6", use_errno=True)

    # Профиль «основной» — пустая строка: слои не накладываются, программа
    # работает с настоящим ~/. Нужен, чтобы «просто через VPN, без контейнера»
    # оставалось возможным.
    if profile_dir:
        for sub in SUBDIRS:
            lower = os.path.join(home, sub)
            if not os.path.isdir(lower):
                continue
            slot = os.path.join(profile_dir, sub.replace("/", "_"))
            upper, work = os.path.join(slot, "upper"), os.path.join(slot, "work")
            os.makedirs(upper, exist_ok=True)
            os.makedirs(work, exist_ok=True)
            try:
                mount_overlay(libc, lower, upper, work, lower)
            except OSError as e:
                print(f"профиль: {e}", file=sys.stderr)
        # Реестр «кто в какой сети запущен» ведёт vpn-zone (общий для профилей и
        # для основного окружения) — здесь дублировать его незачем.

    # Права больше не нужны — снимаем перед запуском программы.
    libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)

    if not ephemeral:
        try:
            os.execvp(cmd[0], cmd)
        except OSError as e:
            print(f"не удалось запустить {cmd[0]}: {e}", file=sys.stderr)
            return 127

    # --- ОДНОРАЗОВЫЙ ПРОФИЛЬ ---
    # Здесь нельзя execvp: кто-то должен пережить программу и убрать за ней
    # каталог. Поэтому запускаем потомком и ждём. Сами точки монтирования
    # чистить не надо — mount namespace исчезает вместе с последним процессом.
    #
    # Оговорка: если программа отправляет себя в фон и сразу завершает первый
    # процесс, ожидание кончится раньше времени и каталог будет удалён у неё из
    # под ног. Браузеры и Electron так себя не ведут (в своём профиле они
    # остаются на переднем плане), но знать об этом стоит.
    pid = os.fork()
    if pid == 0:
        try:
            os.execvp(cmd[0], cmd)
        except OSError as e:
            print(f"не удалось запустить {cmd[0]}: {e}", file=sys.stderr)
            os._exit(127)
    _, status = os.waitpid(pid, 0)

    # Стираем слой только за ПОСЛЕДНИМ жильцом. В один временный контейнер можно
    # подсадить несколько программ (`--tmp-profile --join`), и если удалять по
    # выходу первой, у остальных пропадёт файловая система прямо под руками.
    # Считаем живых по общему реестру запусков, себя из счёта исключаем.
    if others_alive(regdir, os.getpid()):
        print(f"временный контейнер {os.path.basename(profile_dir)} оставлен: в нём ещё работают программы")
    else:
        shutil.rmtree(profile_dir, ignore_errors=True)
        shutil.rmtree(regdir, ignore_errors=True)
    return os.waitstatus_to_exitcode(status) if hasattr(os, "waitstatus_to_exitcode") else 0


if __name__ == "__main__":
    sys.exit(main())
