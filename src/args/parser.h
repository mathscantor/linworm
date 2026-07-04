#ifndef ARGS_PARSER_H
#define ARGS_PARSER_H

#include <getopt.h>
#include <string.h>
#include <regex.h>
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>

#include "../helpers/common.h"
#include "../linworm.h"

typedef struct {
    pid_t ropts_target_pid;
    int oopts_verbose;
} user_args_t;

user_args_t parse_args(int, char* []);
void usage(void);

#endif