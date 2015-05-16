#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

void syscall_init (void);

struct lock sysLock;

#endif /* userprog/syscall.h */
