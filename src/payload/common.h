#ifndef PAYLOAD_COMMON_H
#define PAYLOAD_COMMON_H

#include <stdbool.h>
#include <signal.h>
#include <pthread.h>

/*
 * Shared thread lifecycle framework for linworm payloads.
 *
 * Usage pattern:
 *
 *   static void *my_thread(void *arg) {
 *       while (payload_running()) {
 *           // ... do work ...
 *           payload_sleep_ms(2000);
 *       }
 *       return NULL;
 *   }
 *
 *   __attribute__((constructor))
 *   void on_load(void) {
 *       if (payload_init() == 0)
 *           payload_start(my_thread);
 *   }
 *
 *   __attribute__((destructor))
 *   void on_unload(void) {
 *       if (g_pipe_fd[0] != -1)
 *           payload_stop();
 *   }
 *
 * Send SIGUSR2 to the target process to trigger graceful shutdown
 * and automatically dlclose() the payload library.
 */

extern volatile sig_atomic_t g_running;
extern pthread_t g_thread;
extern int g_pipe_fd[2];
extern void *g_self_handle;

void payload_signal_handler(int sig);
int  payload_init(void);
int  payload_start(void *(*func)(void *));
void payload_stop(void);
bool payload_running(void);
void payload_sleep_ms(int ms);

__attribute__((format(printf, 2, 3)))
void payload_log(const char *logpath, const char *fmt, ...);

#endif /* PAYLOAD_COMMON_H */
