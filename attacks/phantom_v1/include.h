#pragma once

#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <sys/wait.h>
#include <assert.h>
#include <stdbool.h>
#include <linux/userfaultfd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/types.h>
#include <syscall.h>
#include <linux/userfaultfd.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <time.h>
#include <asm/unistd.h>      
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>

#define FORCE_INLINE __attribute__((always_inline)) inline

#define handle_error_en(en, msg) \
  do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)

#ifndef SYS_gettid
#error "SYS_gettid unavailable on this system"
#endif

#define gettid() ((pid_t)syscall(SYS_gettid))

static void* fault_handler_thread(void *arg);

#include "shared.c"
