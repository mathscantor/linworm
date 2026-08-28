#include "common.h"
#include <unistd.h>

#define BEACON_LOG        "/tmp/linworm_beacon.log"
#define BEACON_INTERVAL_MS 2000

static void *beacon_thread(void *arg) {
    (void)arg;
    unsigned long counter = 0;

    payload_log(BEACON_LOG, "beacon started (pid=%d, tid=%ld)",
                getpid(), (long)pthread_self());

    while (payload_running()) {
        payload_log(BEACON_LOG, "heartbeat #%lu (pid=%d)", counter++, getpid());
        payload_sleep_ms(BEACON_INTERVAL_MS);
    }

    payload_log(BEACON_LOG, "beacon shutting down (pid=%d, %lu heartbeats sent)",
                getpid(), counter);
    return NULL;
}

__attribute__((constructor))
void on_load(void) {
    if (payload_init() == 0)
        payload_start(beacon_thread);
}

__attribute__((destructor))
void on_unload(void) {
    if (g_pipe_fd[0] != -1)
        payload_stop();
}
