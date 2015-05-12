#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

/* Struct used to share between process_execute() in the
 * invoking thread and start_process() inside the newly invoked
 * thread.
 */
struct exec_helper {
    const char *file_name;  // Program to load (entire command line)
    bool load_success; // For determining if program loaded successfully
    struct semaphore loading;
    // more stuff here
};

#endif /* userprog/process.h */
