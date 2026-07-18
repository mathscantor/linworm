#include "parser.h"

static bool is_valid_integer(const char *str);
static bool is_valid_pid(const char *str);

/**
 * @brief Parses command-line arguments and returns a structured representation.
 * 
 * This function processes the command-line arguments passed to the program,
 * extracting relevant options and flags to populate a `user_args_t` structure.
 * It validates input parameters and ensures proper usage.
 * 
 * @param argc The number of command-line arguments.
 * @param argv An array of argument strings.
 * @return user_args_t A structure containing parsed argument values.
 *                     If an error occurs, appropriate error handling should be performed.
 */
user_args_t parse_args(int argc, char *argv[]) {

    int opt;
    int option_index = 0;

    user_args_t user_args = {
        .oopts_verbose = 1,
        .ropts_target_pid = -1,
        .ropts_library_path = NULL
    };    

    struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
        {"verbose", no_argument, 0, 'v'},
        {"pid", required_argument, 0, 'p'},
        {"library", required_argument, 0, 'l'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "hVvp:l:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h':
                usage();
                exit(EXIT_SUCCESS);
                break;
            case 'v':
                user_args.oopts_verbose = 2; 
                break;
            case 'V':
                printf("linworm %s\n", LINWORM_VERSION_STR);
                exit(EXIT_SUCCESS);
                break;
            case 'p':
                if (!is_valid_pid(optarg)) {
                    log_message(ERROR, __func__, "Invalid PID specified.");
                    usage();
                    exit(EXIT_FAILURE);
                }
                user_args.ropts_target_pid = atoi(optarg);
                break;
            case 'l':
                user_args.ropts_library_path = optarg;
                break;
            default:
                usage();
                exit(EXIT_FAILURE);
        }
    }

    if (user_args.ropts_target_pid == -1) {
        log_message(ERROR, __func__, "Target PID is required.");
        usage();
        exit(EXIT_FAILURE);
    }

    if (user_args.ropts_library_path == NULL) {
        log_message(ERROR, __func__, "Library path is required.");
        usage();
        exit(EXIT_FAILURE);
    }

    if (optind < argc) {
        log_message(ERROR, __func__, "linworm does not take in any positional arguments! See usage.");
        usage();
        exit(EXIT_FAILURE);
    }
    return user_args;
}

/**
 * @brief Prints the usage of linworm.
 * 
 */
void usage(void){
    printf("Usage: linworm -p TARGET_PID -l LIBRARY_PATH [-h] [-v] [-V] \n");
    printf("Options:\n");
    printf("  %-30s %s\n", "-h  | --help", "Show help");
    printf("  %-30s %s\n", "-v  | --verbose", "Enables debug logs.");
    printf("  %-30s %s\n", "-V  | --version", "Show the version of linworm.");
    printf("  %-30s %s\n", "-p  | --pid", "Target process ID to inject into.");
    printf("  %-30s %s\n", "-l  | --library", "Path to the shared library (.so) to inject.");
    return;
} 

/**
 * @brief Checks if the given string represents a valid integer.
 * 
 * This function attempts to convert the input string to a long integer using
 * `strtol`. It ensures the string is a valid integer representation by checking
 * for errors such as out-of-range values, invalid characters, or empty strings.
 * 
 * @param str The string to check.
 * @return `true` if the string is a valid integer, `false` otherwise.
 * 
 * @note The function uses `strtol` to convert the string and checks for errors
 * like out-of-range values (`LONG_MAX`, `LONG_MIN`) and invalid characters.
 * It also ensures the string doesn't contain extraneous non-numeric characters.
 */
static bool is_valid_integer(const char *str) {
    char *endptr;
    errno = 0;

    long val = strtol(str, &endptr, 10);

    if (errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) {
        return false;
    }

    if (errno != 0 && val == 0) {
        return false;
    }

    if (endptr == str) {
        return false;
    }

    if (*endptr != '\0') {
        return false;
    }

    return true;
}

static bool is_valid_pid(const char *str) {
    if (str == NULL || *str == '\0') {
        return false;
    }

    if (!is_valid_integer(str)) {
        return false;
    }

    long pid = strtol(str, NULL, 10);
    return pid > 0;
}