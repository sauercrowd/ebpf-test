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
	if (!PT_REGS_PARM1(ctx))
		return 0;
	strlenkey_t key;
	u64 zero = 0, *val;
	bpf_probe_read(&key, sizeof(key), (void *)PT_REGS_PARM1(ctx));
	val = counts.lookup_or_init(&key, &zero);
	(*val)++;
	return 0;
}
`

var ansiEscape = regexp.MustCompile(`[[:cntrl:]]`)

func main() {
	log.Println(quote.Hello())
	m := bpf.NewModule(source, []string{})
	defer m.Close()
	uprobe, err := m.LoadUprobe("count")
	if err != nil {
		log.Fatal(err)
	}
	if err := m.AttachUprobe("c", "strlen", uprobe, -1); err != nil {
		log.Fatal(err)
	}

	table := bpf.NewTable(m.TableId("counts"), m)

	fmt.Println("Tracing strlen()... hit Ctrl-C to end.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig

	fmt.Printf("%10s %s\n", "COUNT", "STRING")
	for it := table.Iter(); it.Next(); {
		k := ansiEscape.ReplaceAll(it.Key(), []byte{})
		v := binary.LittleEndian.Uint64(it.Leaf())
		fmt.Printf("%10d \"%s\"\n", v, k)
	}
}
