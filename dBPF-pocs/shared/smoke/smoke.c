#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "smoke.skel.h"

static volatile int stop;
static void sig(int _){ stop=1; }

static int handle(void *ctx, void *data, size_t sz){
    unsigned int cap = *(unsigned int*)data;
    printf("cap_capable cap=%u\n", cap);
    return 0;
}

int main(void){
    struct smoke_bpf *s = smoke_bpf__open_and_load();
    if(!s){ fprintf(stderr,"open_and_load failed\n"); return 1;}
    if(smoke_bpf__attach(s)){ fprintf(stderr,"attach failed\n"); return 1;}
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(s->maps.events), handle, NULL, NULL);
    signal(SIGINT,sig); signal(SIGTERM,sig);
    fprintf(stderr,"attached — trigger capability checks...\n");
    while(!stop){ ring_buffer__poll(rb, 200); }
    ring_buffer__free(rb); smoke_bpf__destroy(s);
    return 0;
}
