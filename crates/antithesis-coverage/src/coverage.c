// Antithesis coverage runtime shim, adapted from antithesis_instrumentation.h in
// antithesis-instrumentation 0.1.1 (MIT, https://github.com/antithesishq/antithesis-instrumentation-rust).
// The only change: antithesis_load_libvoidstar() does nothing when
// TEMPO_ANTITHESIS_COVERAGE_DISABLED is set to a non-empty value (see src/lib.rs).

#include <dlfcn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(__clang__)
#define NO_SANITIZE_COVERAGE __attribute__((no_sanitize("coverage")))
#else
#define NO_SANITIZE_COVERAGE
#endif

typedef void (*trace_pc_guard_init_fn)(uint32_t *start, uint32_t *stop);
typedef void (*trace_pc_guard_fn)(uint32_t *guard, uint64_t edge);

static trace_pc_guard_init_fn trace_pc_guard_init = NULL;
static trace_pc_guard_fn trace_pc_guard = NULL;
static bool did_check_libvoidstar = false;
static bool has_libvoidstar = false;

static NO_SANITIZE_COVERAGE void debug_message_out(const char *msg) {
    if (getenv("ANTITHESIS_OUTPUT_DIR") != NULL) {
        (void)fprintf(stderr, "%s\n", msg);
    }
}

static NO_SANITIZE_COVERAGE bool coverage_disabled(void) {
    const char *value = getenv("TEMPO_ANTITHESIS_COVERAGE_DISABLED");
    return value != NULL && value[0] != '\0';
}

NO_SANITIZE_COVERAGE void antithesis_load_libvoidstar(void) {
    if (did_check_libvoidstar) {
        return;
    }
    did_check_libvoidstar = true;
    if (coverage_disabled()) {
        debug_message_out("Antithesis coverage disabled: not loading libvoidstar");
        return;
    }
    debug_message_out("TRYING TO LOAD libvoidstar");
    void *shared_lib = dlopen("/usr/lib/libvoidstar.so", RTLD_NOW);
    if (!shared_lib) {
        debug_message_out("Can not load the Antithesis native library");
        return;
    }
    void *init_sym = dlsym(shared_lib, "__sanitizer_cov_trace_pc_guard_init");
    if (!init_sym) {
        debug_message_out("Can not forward calls to libvoidstar for __sanitizer_cov_trace_pc_guard_init");
        return;
    }
    void *guard_sym = dlsym(shared_lib, "__sanitizer_cov_trace_pc_guard_internal");
    if (!guard_sym) {
        debug_message_out("Can not forward calls to libvoidstar for __sanitizer_cov_trace_pc_guard");
        return;
    }
    trace_pc_guard_init = (trace_pc_guard_init_fn)init_sym;
    trace_pc_guard = (trace_pc_guard_fn)guard_sym;
    has_libvoidstar = true;
    debug_message_out("LOADED libvoidstar");
}

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wreserved-identifier"
#endif

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
    if (!did_check_libvoidstar) {
        antithesis_load_libvoidstar();
    }
    if (has_libvoidstar) {
        trace_pc_guard_init(start, stop);
    }
}

void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    if (has_libvoidstar) {
        trace_pc_guard(guard, (uint64_t)__builtin_return_address(0));
    } else if (guard) {
        *guard = 0;
    }
}

// Binaries built with -sanitizer-coverage-pc-table call this once per module.
void __sanitizer_cov_pcs_init(const uintptr_t *pcs_beg, const uintptr_t *pcs_end) {
    (void)pcs_beg;
    (void)pcs_end;
}

#if defined(__clang__)
#pragma clang diagnostic pop
#endif
