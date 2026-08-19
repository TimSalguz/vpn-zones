// wl-sandbox — запускает программу с ОГРАНИЧЕННЫМ доступом к Wayland.
//
// ЗАЧЕМ. Композитор выдаёт любому клиенту протоколы, которыми тот может снять
// экран (wlr-screencopy), читать буфер обмена в фоне (data-control), печатать и
// двигать мышь за пользователя (virtual-keyboard, virtual-pointer) и видеть
// список чужих окон (foreign-toplevel). Ни один из них не спрашивает разрешения:
// в протоколе нет понятия «доверенный клиент», а нужны они для нормальных вещей —
// скриншотилок, менеджера буфера, автоматизации.
//
// Различать клиентов позволяет протокол wp_security_context_v1. Клиент создаёт
// ОТДЕЛЬНЫЙ unix-сокет, помечает его как песочницу и отдаёт композитору. Все, кто
// подключится через этот сокет, считаются ограниченными. niri (см. функцию
// client_is_unrestricted в его исходниках) и KWin такие протоколы им не выдают
// вовсе — программа не «получает отказ», она их просто не видит.
//
// Что у программы ОСТАЁТСЯ: свои окна, ввод в них, буфер обмена при фокусе (то
// есть обычные Ctrl+C/Ctrl+V), GPU, звук. Теряется только слежка.
//
// ЕСЛИ ПРОТОКОЛА НЕТ (старый композитор, X11-сессия) — программа запускается как
// обычно. Молча ослаблять защиту нехорошо, поэтому пишем предупреждение в stderr.
//
// Использование: wl-sandbox <app-id> <команда> [аргументы…]

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <wayland-client.h>

#include "security-context-v1-client-protocol.h"

static struct wp_security_context_manager_v1 *manager = NULL;

static void registry_global(void *data, struct wl_registry *registry, uint32_t name,
                            const char *interface, uint32_t version) {
    (void)data;
    (void)version;
    if (strcmp(interface, wp_security_context_manager_v1_interface.name) == 0) {
        manager = wl_registry_bind(registry, name, &wp_security_context_manager_v1_interface, 1);
    }
}

static void registry_global_remove(void *data, struct wl_registry *registry, uint32_t name) {
    (void)data; (void)registry; (void)name;
}

static const struct wl_registry_listener registry_listener = {
    .global = registry_global,
    .global_remove = registry_global_remove,
};

// Запуск без ограничений — общий путь для всех случаев «не получилось».
static int run_plain(char **argv) {
    execvp(argv[0], argv);
    fprintf(stderr, "wl-sandbox: не удалось запустить %s: %s\n", argv[0], strerror(errno));
    return 127;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "использование: wl-sandbox <app-id> <команда> [аргументы…]\n");
        return 2;
    }
    const char *app_id = argv[1];
    char **cmd = &argv[2];

    const char *runtime_dir = getenv("XDG_RUNTIME_DIR");
    if (!runtime_dir) {
        fprintf(stderr, "wl-sandbox: нет XDG_RUNTIME_DIR — запускаю без ограничений\n");
        return run_plain(cmd);
    }

    struct wl_display *display = wl_display_connect(NULL);
    if (!display) {
        fprintf(stderr, "wl-sandbox: нет связи с композитором — запускаю без ограничений\n");
        return run_plain(cmd);
    }

    struct wl_registry *registry = wl_display_get_registry(display);
    wl_registry_add_listener(registry, &registry_listener, NULL);
    wl_display_roundtrip(display);

    if (!manager) {
        fprintf(stderr,
                "wl-sandbox: композитор не поддерживает security-context — "
                "запускаю %s без ограничений\n", cmd[0]);
        wl_display_disconnect(display);
        return run_plain(cmd);
    }

    // Свой сокет для этой программы. Имя уникально по pid: два запуска одной
    // программы не должны драться за один путь.
    char sock_name[64];
    snprintf(sock_name, sizeof(sock_name), "wl-sandbox-%d", (int)getpid());

    char sock_path[256];
    snprintf(sock_path, sizeof(sock_path), "%s/%s", runtime_dir, sock_name);
    unlink(sock_path);

    int listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listen_fd < 0) {
        perror("wl-sandbox: socket");
        return run_plain(cmd);
    }
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sock_path);
    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 || listen(listen_fd, 16) < 0) {
        perror("wl-sandbox: bind/listen");
        close(listen_fd);
        return run_plain(cmd);
    }

    // close_fd — «выключатель». Композитор перестаёт принимать соединения на
    // сокет, когда этот конец трубы закрывается; держим его открытым, пока
    // программа работает, и отпускаем после её выхода.
    int close_pipe[2];
    if (pipe(close_pipe) < 0) {
        perror("wl-sandbox: pipe");
        close(listen_fd);
        return run_plain(cmd);
    }

    struct wp_security_context_v1 *ctx =
        wp_security_context_manager_v1_create_listener(manager, listen_fd, close_pipe[0]);
    wp_security_context_v1_set_sandbox_engine(ctx, "vpn-zone");
    wp_security_context_v1_set_app_id(ctx, app_id);
    char instance_id[64];
    snprintf(instance_id, sizeof(instance_id), "%d", (int)getpid());
    wp_security_context_v1_set_instance_id(ctx, instance_id);
    wp_security_context_v1_commit(ctx);
    wl_display_roundtrip(display);

    // Наши копии отданных дескрипторов больше не нужны: у композитора свои.
    close(listen_fd);
    close(close_pipe[0]);
    wp_security_context_v1_destroy(ctx);
    wl_display_disconnect(display);

    setenv("WAYLAND_DISPLAY", sock_name, 1);
    // WAYLAND_SOCKET (унаследованный дескриптор) перебил бы WAYLAND_DISPLAY, и
    // программа ушла бы на обычный сокет мимо всей затеи.
    unsetenv("WAYLAND_SOCKET");

    pid_t pid = fork();
    if (pid < 0) {
        perror("wl-sandbox: fork");
        return run_plain(cmd);
    }
    if (pid == 0) {
        close(close_pipe[1]);
        return run_plain(cmd);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    close(close_pipe[1]);   // сокет закрывается вместе с программой
    unlink(sock_path);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
