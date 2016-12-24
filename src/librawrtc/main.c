#include <pthread.h> // pthread_*
#include <rawrtc.h>
#include "main.h"

#define DEBUG_MODULE "rawrtc-main"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

struct rawrtc_global {
    pthread_mutex_t mutex;
    pthread_t mutex_main_thread;
    uint_fast16_t mutex_counter;
};

static struct rawrtc_global global;

/*
 * Initialise rawrtc. Must be called before making a call to any other
 * function
 */
enum rawrtc_code rawrtc_init() {
    int err;
    pthread_mutexattr_t mutex_attribute;

    // Initialise re
    if (libre_init()) {
        return RAWRTC_CODE_INITIALISE_FAIL;
    }

    // Initialise and set mutex attribute
    // Note: A recursive mutex is required as an upcall can trigger an upcall.
    err = pthread_mutexattr_init(&mutex_attribute);
    if (err) {
        DEBUG_WARNING("Failed to initialise mutex attribute, reason: %m\n", err);
        return rawrtc_error_to_code(err);
    }
    err = pthread_mutexattr_settype(&mutex_attribute, PTHREAD_MUTEX_RECURSIVE);
    if (err) {
        DEBUG_WARNING("Failed to set mutex attribute, reason: %m\n", err);
        return rawrtc_error_to_code(err);
    }

    // Initialise mutex
    err = pthread_mutex_init(&global.mutex, &mutex_attribute);
    if (err) {
        DEBUG_WARNING("Failed to initialise mutex, reason: %m\n", err);
        return rawrtc_error_to_code(err);
    }

    // Set main thread and counter
    global.mutex_main_thread = pthread_self();
    global.mutex_counter = 0;

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Close rawrtc and free up all resources.
 */
enum rawrtc_code rawrtc_close() {
    int err;

    // TODO: Close usrsctp if initialised

    // Destroy mutex
    err = pthread_mutex_destroy(&global.mutex);
    if (err) {
        DEBUG_WARNING("Failed to destroy mutex, reason: %m\n", err);
    }

    // Close re
    libre_close();

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Lock event loop mutex (re-entrant).
 */
void rawrtc_thread_enter() {
    int err;

    // Need locking?
    if (pthread_equal(global.mutex_main_thread, pthread_self())) {
        DEBUG_PRINTF("Already on event loop thread, no locking required\n");
        return;
    }

    // Lock mutex
    err = pthread_mutex_lock(&global.mutex);
    if (err) {
        DEBUG_WARNING("Unable to lock mutex, reason: %m\n", err);
    }
    DEBUG_PRINTF("Locked reentrant mutex\n");

    // Lock event loop mutex
    if (global.mutex_counter == 0) {
        re_thread_enter();
        DEBUG_PRINTF("Locked event loop mutex\n");
    }

    // Increase counter
    ++global.mutex_counter;
}

/*
 * Release event loop mutex (re-entrant).
 */
void rawrtc_thread_leave() {
    int err;

    // Need unlocking?
    if (pthread_equal(global.mutex_main_thread, pthread_self())) {
        DEBUG_PRINTF("Already on event loop thread, no unlocking required\n");
        return;
    }

    // Decrease counter
    --global.mutex_counter;

    // Unlock event loop mutex
    if (global.mutex_counter == 0) {
        DEBUG_PRINTF("Unlocking event loop mutex\n");
        re_thread_leave();
    }

    // Unlock mutex
    DEBUG_PRINTF("Unlocking reentrant mutex\n");
    err = pthread_mutex_unlock(&global.mutex);
    if (err) {
        DEBUG_WARNING("Unable to unlock mutex, reason: %m\n", err);
    }
}
