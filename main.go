package main

import (
	bpf "github.com/iovisor/gobpf/bcc"
	"log"
	"rsc.io/quote"
)

const source string = `
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(currsock, u32, struct sock *);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk){
	u32 pid = bpf_get_current_pid_tgid();
	currsock.update(&pid, &sk);
	return 0;
}

int kretprobe__tcp_v4_connect(struct pt_regs *ctx){
	int ret = PT_REGS_RC(ctx);
	u32 pid = bpf_get_current_pid_tgid();

	struct sock **skpp;
	skpp = currsock.lookup(&pid);
	if (skpp == 0){
		return 0;
	}

	if (ret!= 0){
		// failed to send SYNC packet
		currsock.delete(&pid);
		return 0;
	}

	struct sock *skp = *skpp;
	u32 saddr = 0, daddr = 0;
	u16 dport = 0;

	bpf_probe_read(&saddr, sizeof(saddr), &skp->__sk_common.skc_rcv_saddr);
	bpf_probe_read(&daddr, sizeof(daddr), &skp->__sk_common.skc_daddr);
	bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);
	// output
	bpf_trace_printk("trace_tcp4connect %x %x %d\\n", saddr, daddr, ntohs(dport));
	currsock.delete(&pid);
	return 0;

}
`

func main() {
	log.Println(quote.Hello())
	m := bpf.NewModule(source, []string{})
	defer m.Close()

	kprobe, err := m.LoadKprobe("kprobe__tcp_v4_connect")
	if err != nil {
		log.Println(err)
	}
	if err := m.AttachKprobe("tcp_v4_connect", kprobe); err != nil {
		log.Println(err)
	}
}
