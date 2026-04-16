#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "ch04-phantom-syscall.skel.h"

struct evt {
    unsigned int pid, tgid, uid, euid;
    char comm[16];
    char parent_comm[16];
    char payload[32];
};

static volatile int stop;
static void sig(int _){ (void)_; stop=1; }

static int handle(void *ctx, void *data, size_t sz){
    (void)ctx; (void)sz;
    struct evt *e = data;
    printf("[phantom] pid=%u tgid=%u uid=%u euid=%u comm=%s parent=%s payload='%s'\n",
           e->pid, e->tgid, e->uid, e->euid, e->comm, e->parent_comm, e->payload);
    return 0;
}

int main(void){
    struct ch04_phantom_syscall_bpf *s = ch04_phantom_syscall_bpf__open_and_load();
    if(!s){ fprintf(stderr,"open_and_load failed\n"); return 1; }
    // Prevent stage2 from auto-attaching to sys_enter_write directly.
    bpf_program__set_autoattach(s->progs.phantom_stage2, false);
    int stage2_fd = bpf_program__fd(s->progs.phantom_stage2);
    unsigned int k = 0;
    bpf_map__update_elem(s->maps.jumps, &k, sizeof(k), &stage2_fd, sizeof(stage2_fd), BPF_ANY);
    if(ch04_phantom_syscall_bpf__attach(s)){ fprintf(stderr,"attach failed\n"); return 1; }
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(s->maps.events), handle, NULL, NULL);
    signal(SIGINT,sig); signal(SIGTERM,sig);
    fprintf(stderr,"attached — phantom active (magic: 'PHANTOM\\0')\n");
    while(!stop) ring_buffer__poll(rb, 200);
    ring_buffer__free(rb); ch04_phantom_syscall_bpf__destroy(s);
    return 0;
}
