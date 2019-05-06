package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"regexp"

	bpf "github.com/iovisor/gobpf/bcc"
	"rsc.io/quote"
)

import "C"

const source string = `
#include <uapi/linux/ptrace.h>

typedef char strlenkey_t[80];
BPF_HASH(counts, strlenkey_t);
int count(struct pt_regs *ctx) {
	if (!PT_REGS_PARM3(ctx))
		return 0;
	if (!PT_REGS_PARM2(ctx))
		return 0;
	if (PT_REGS_PARM2(ctx) != 10002)
		return 0;

	strlenkey_t key;
	u64 zero = 0, *val;
	bpf_probe_read_str(&key, sizeof(strlenkey_t), (void *)PT_REGS_PARM3(ctx));
	val = counts.lookup_or_init(&key, &zero);
	(*val)++;
	return 0;
}
`

var ansiEscape = regexp.MustCompile(`[[:cntrl:]]`)

func main() {
	log.Println(quote.Hello())
	ccflags := []string{
		"-I/usr/lib/gcc/x86_64-linux-gnu/7/include",
		"-I/usr/local/include",
		"-I/usr/lib/gcc/x86_64-linux-gnu/7/include-fixed",
		"-I/usr/include/x86_64-linux-gnu",
		"-I/usr/include",
	}
	m := bpf.NewModule(source, ccflags)
	defer m.Close()
	uprobe, err := m.LoadUprobe("count")
	if err != nil {
		log.Fatal(err)
	}
	if err := m.AttachUprobe("curl", "curl_easy_setopt", uprobe, -1); err != nil {
		log.Fatal(err)
	}

	table := bpf.NewTable(m.TableId("counts"), m)

	fmt.Println("Tracing strlen()... hit Ctrl-C to end.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig

	fmt.Printf("%10s %s\n", "COUNT", "STRING")
	for it := table.Iter(); it.Next(); {
		v := binary.LittleEndian.Uint64(it.Leaf())
		fmt.Printf("%10d | %s\n", v, it.Key())
	}
}
