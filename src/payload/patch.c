#include "common.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>

#define PATCH_LOG "/tmp/linworm_patch.log"

/* ------------------------------------------------------------------ */
/*  Patch entry descriptor                                            */
/* ------------------------------------------------------------------ */

#define MAX_PATCH_LEN 16

typedef struct {
    unsigned long offset;
    uint8_t       patch_bytes[MAX_PATCH_LEN];
    uint8_t       orig_bytes[MAX_PATCH_LEN];
    size_t        len;
} patch_entry_t;

/* ------------------------------------------------------------------ */
/*  User-defined patch configuration                                  */
/*                                                                    */
/*  PATCH_TARGET  — substring matched against /proc/self/maps path    */
/*                  column.  Works for both the main binary            */
/*                  (e.g. "example_target") and shared libraries       */
/*                  (e.g. "libc.so.6").                                */
/*                                                                    */
/*  PATCHES[]     — table of patch entries.  Each entry specifies an  */
/*                  offset from the module base, the replacement      */
/*                  bytes, the original bytes, and the byte count.    */
/*                  Add rows to patch more locations.                 */
/*                                                                    */
/*  Current example: change the return value of sleep_func() from 0   */
/*  to -1 by overwriting the immediate operand of "mov eax, 0x0"     */
/*  (at offset 0x4aa the opcode B8 lives; the 4-byte immediate       */
/*  starts at 0x4ab).                                                 */
/* ------------------------------------------------------------------ */

#define PATCH_TARGET "example_target"

static const patch_entry_t PATCHES[] = {
    { 
        .offset = 0x4ab, 
        .patch_bytes = { 0xff, 0xff, 0xff, 0xff }, 
        .orig_bytes  = { 0x00, 0x00, 0x00, 0x00 }, 
        .len = 4 
    },
    /* add more entries here */
};

#define PATCH_COUNT (sizeof(PATCHES) / sizeof(patch_entry_t))

/* Resolved runtime addresses — one per PATCHES[] entry. */
static uint8_t *g_patch_sites[PATCH_COUNT];
static size_t   g_applied_count = 0;

static int set_page_perms(void *addr, int prot) {
    long page_size = sysconf(_SC_PAGESIZE);
    void *page = (void *)((uintptr_t)addr & ~(page_size - 1));
    return mprotect(page, page_size, prot);
}

/*
 * Scan /proc/self/maps for the first mapping whose path contains `target`
 * and return its start address.  Works for both the main executable and
 * any shared library loaded into the process.
 */
static void *find_module_base(const char *target) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f)
        return NULL;

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, target))
            continue;

        unsigned long start;
        if (sscanf(line, "%lx-", &start) == 1) {
            fclose(f);
            return (void *)start;
        }
    }

    fclose(f);
    return NULL;
}

static int apply_patch(uint8_t *site, const uint8_t *bytes, size_t len) {
    if (set_page_perms(site, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        return -1;
    memcpy(site, bytes, len);
    if (set_page_perms(site, PROT_READ | PROT_EXEC) != 0)
        return -1;
    return 0;
}

static void *patch_thread(void *arg) {
    (void)arg;

    payload_log(PATCH_LOG, "%zu patch(es) active (pid=%d)",
                g_applied_count, getpid());

    while (payload_running())
        payload_sleep_ms(1000);

    for (size_t i = g_applied_count; i-- > 0; ) {
        if (apply_patch(g_patch_sites[i], PATCHES[i].orig_bytes,
                        PATCHES[i].len) == 0)
            payload_log(PATCH_LOG, "patch[%zu] unpatched at %p (pid=%d)",
                        i, (void *)g_patch_sites[i], getpid());
        else
            payload_log(PATCH_LOG, "patch[%zu] unpatch failed at %p (pid=%d)",
                        i, (void *)g_patch_sites[i], getpid());
    }

    return NULL;
}

__attribute__((constructor))
void on_load(void) {
    if (payload_init() != 0)
        return;

    void *base = find_module_base(PATCH_TARGET);
    if (!base) {
        payload_log(PATCH_LOG, "module \"%s\" not found in /proc/self/maps",
                    PATCH_TARGET);
        return;
    }

    payload_log(PATCH_LOG, "target \"%s\" base=%p, applying %zu patch(es) (pid=%d)",
                PATCH_TARGET, base, PATCH_COUNT, getpid());

    for (size_t i = 0; i < PATCH_COUNT; i++) {
        uint8_t *site = (uint8_t *)base + PATCHES[i].offset;

        if (apply_patch(site, PATCHES[i].patch_bytes, PATCHES[i].len) != 0) {
            payload_log(PATCH_LOG, "patch[%zu] failed at offset 0x%lx (%p)",
                        i, PATCHES[i].offset, (void *)site);
            continue;
        }

        g_patch_sites[i] = site;
        g_applied_count++;
        payload_log(PATCH_LOG, "patch[%zu] applied %zu byte(s) at offset 0x%lx (%p)",
                    i, PATCHES[i].len, PATCHES[i].offset, (void *)site);
    }

    if (g_applied_count > 0)
        payload_start(patch_thread);
    else
        payload_log(PATCH_LOG, "no patches applied — not starting monitor thread");
}

__attribute__((destructor))
void on_unload(void) {
    if (g_pipe_fd[0] != -1)
        payload_stop();
}
