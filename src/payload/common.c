#include "common.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <poll.h>

volatile sig_atomic_t g_running = 0;
pthread_t g_thread;
int g_pipe_fd[2] = {-1, -1};

/*
 * Async-signal-safe handler. Sets the flag and writes to the self-pipe
 * so that payload_sleep_ms() returns immediately.
 */
void payload_signal_handler(int sig) {
    (void)sig;
    g_running = 0;
    const char byte = 1;
    (void)write(g_pipe_fd[1], &byte, 1);
}

/*
 * Create the self-pipe and install the SIGUSR2 handler.
 * Returns 0 on success, -1 on failure.
 */
int payload_init(void) {
    if (pipe(g_pipe_fd) == -1)
        return -1;

    fcntl(g_pipe_fd[0], F_SETFL, O_NONBLOCK);
    fcntl(g_pipe_fd[1], F_SETFL, O_NONBLOCK);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = payload_signal_handler;
    sa.sa_flags = SA_RESTART;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGUSR2, &sa, NULL) == -1) {
        close(g_pipe_fd[0]);
        close(g_pipe_fd[1]);
        g_pipe_fd[0] = g_pipe_fd[1] = -1;
        return -1;
    }

    g_running = 1;
    return 0;
}

/* Spawn the worker thread. Returns 0 on success, non-zero errno on failure. */
int payload_start(void *(*func)(void *)) {
    return pthread_create(&g_thread, NULL, func, NULL);
}

/*
 * Signal the worker thread to stop and wait for it to finish.
 * Closes the self-pipe.
 */
void payload_stop(void) {
    g_running = 0;
    const char byte = 1;
    (void)write(g_pipe_fd[1], &byte, 1);

    pthread_join(g_thread, NULL);

    close(g_pipe_fd[0]);
    close(g_pipe_fd[1]);
    g_pipe_fd[0] = g_pipe_fd[1] = -1;
}

/* Returns true while the thread should keep running. */
bool payload_running(void) {
    return g_running != 0;
}

/*
 * Sleep for up to `ms` milliseconds, returning early if the
 * shutdown signal fires (the self-pipe becomes readable).
 */
void payload_sleep_ms(int ms) {
    struct pollfd pfd = {
        .fd = g_pipe_fd[0],
        .events = POLLIN,
    };
    poll(&pfd, 1, ms);

    if (pfd.revents & POLLIN) {
        char drain[16];
        while (read(g_pipe_fd[0], drain, sizeof(drain)) > 0)
            ;
    }
}

/*
 * Append a timestamped line to the given log file.
 * Thread-safe: opens/closes per call so no stale handles.
 */
void payload_log(const char *logpath, const char *fmt, ...) {
    FILE *f = fopen(logpath, "a");
    if (!f)
        return;

    time_t now = time(NULL);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_buf);

    fprintf(f, "[%s] ", ts);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);

    fputc('\n', f);
    fclose(f);
}
