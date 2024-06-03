#include "include.h"
#include "config.h"

pthread_mutex_t count_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t condition_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t condition_cond  = PTHREAD_COND_INITIALIZER;

static int page_size;
static volatile char *page = NULL;
int count = 0;

static volatile void write_char(char *string, int len) {
    for(int i = 0; i < len; i++) {
        page[i] = string[i];
    }
}

FORCE_INLINE void receiver() {
    for(;;) {
        pthread_mutex_lock( &condition_mutex );

        while( count >= COUNT_HALT1 && count <= COUNT_HALT2 )
            pthread_cond_wait( &condition_cond, &condition_mutex );

        pthread_mutex_unlock( &condition_mutex );

        pthread_mutex_lock( &count_mutex );
        count++;

        pthread_mutex_unlock( &count_mutex );

        if(count >= COUNT_DONE)
            return;
    }
}

FORCE_INLINE void sender() {
    for(;;) {
        pthread_mutex_lock( &condition_mutex );
        if( count < COUNT_HALT1 || count > COUNT_HALT2 )
	        pthread_cond_signal( &condition_cond );

        pthread_mutex_unlock( &condition_mutex );

        pthread_mutex_lock( &count_mutex );
        count++;

        pthread_mutex_unlock( &count_mutex );

        if(count >= COUNT_DONE)
            return;
    }
}

static inline void flush(void *p) {
    asm volatile("clflush 0(%0)\n" : : "c"(p) : "rax");
}

FORCE_INLINE void set_affinity(int cpuid) {
    int s;
    cpu_set_t cpuset;
    pthread_t thread;

    CPU_ZERO(&cpuset);
    CPU_SET(cpuid, &cpuset);

    thread = pthread_self();
    s = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
    if (s != 0)
        handle_error_en(s, "pthread_setaffinity_np");

    s = pthread_getaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
    if (s != 0)
        handle_error_en(s, "pthread_getaffinity_np");

    printf("TID: %d. ", gettid());
    printf("Set returned by pthread_getaffinity_np() contained:\n");
    if (CPU_ISSET(cpuid, &cpuset))
        printf("    CPU %d\n", cpuid);
    else 
        printf("wrong CPU");
}

int userfaultfd_setup(char *addr, int num_pages) {
    long uffd;
    unsigned long len;
    pthread_t thr;
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;
    int s;

    page_size = sysconf(_SC_PAGE_SIZE);
    len = num_pages * page_size;

    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd == -1)
        handle_error_en(-1, "userfaultfd");

    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
        handle_error_en(-1, "ioctl-UFFDIO_API");

    uffdio_register.range.start = (unsigned long) addr;
    uffdio_register.range.len = len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
        handle_error_en(-1, "ioctl-UFFDIO_REGISTER");

    s = pthread_create(&thr, NULL, fault_handler_thread, (void *) uffd);
    if (s != 0)
        handle_error_en(s, "pthread_create");
}

static int get_policy(char p, int *policy) {
    switch (p) {
    case 'f':
        *policy = SCHED_FIFO;
        return 1;
    case 'r':
        *policy = SCHED_RR;
        return 1;
    case 'o':
        *policy = SCHED_OTHER;
        return 1;
    case 'i':
        *policy = SCHED_IDLE;
        return 1;
    default:
        return 0;
    }
}

static void display_sched_attr(int policy, struct sched_param *param) {
    printf("    policy=%s, priority=%d\n",
        (policy == SCHED_FIFO)  ? "SCHED_FIFO" :
        (policy == SCHED_RR)    ? "SCHED_RR" :
        (policy == SCHED_OTHER) ? "SCHED_OTHER" :
        (policy == SCHED_IDLE)  ? "SCHED_IDLE" :
        "???",
        param->sched_priority);
}

static void display_thread_sched_attr(char *msg) {
    int policy, s;
    struct sched_param param;

    s = pthread_getschedparam(pthread_self(), &policy, &param);
    if (s != 0)
        handle_error_en(s, "pthread_getschedparam");

    printf("%s\n", msg);
    display_sched_attr(policy, &param);
}

void set_child_scheduling(pthread_attr_t* attr, int policy, int priority) {
    int s;
    struct sched_param param;

    param.sched_priority = priority;

    s = pthread_attr_setschedpolicy(attr, policy);
    if (s != 0)
        handle_error_en(s, "pthread_attr_setschedpolicy");

    s = pthread_attr_setschedparam(attr, &param);
    if (s != 0)
        handle_error_en(s, "pthread_attr_setschedparam");
    
    display_thread_sched_attr("Scheduler settings of main thread");
    printf("\n");
}
