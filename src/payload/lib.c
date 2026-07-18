#include <stdio.h>
#include <unistd.h>

// This function is automatically called when the shared library is loaded into a process.
// How it works: The constructor attribute tells the compiler to mark this function to be executed first
__attribute__((constructor))
void on_load(void) {
    printf("[payload] Library injected into PID %d!\n", getpid());
    fflush(stdout);
}
