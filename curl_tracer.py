from bcc import BPF
from time import sleep
import ctypes as ct

CURLOPT_URL=10002

prog="""
#include <uapi/linux/ptrace.h>

typedef struct
{
    char input[64];
} keytype;

BPF_HASH(counts, keytype);

int curl_easy_count(struct pt_regs *ctx) {
	if (!PT_REGS_PARM3(ctx))
		return 0;
	if (!PT_REGS_PARM2(ctx))
		return 0;
	if (PT_REGS_PARM2(ctx) != %d)
		return 0;
	keytype key;
	u64 zero = 0, *val;
	bpf_probe_read_str(&key.input, sizeof(key.input), (void *) PT_REGS_PARM3(ctx));
	val = counts.lookup_or_init(&key, &zero);
	(*val)++;
	return 0;
}

int libc_getnameinfo_count(struct pt_regs *ctx){
	if (!PT_REGS_PARM3(ctx))
		return 0;
	keytype key;
	u64 zero = 0, *val;
	bpf_probe_read_str(&key.input, sizeof(key.input), (void *) PT_REGS_PARM3(ctx));
	val = counts.lookup_or_init(&key, &zero);
	(*val)++;
	return 0;
}

int libc_gethostbyname_count(struct pt_regs *ctx){
	if (!PT_REGS_PARM1(ctx))
		return 0;
	keytype key;
	u64 zero = 0, *val;
	bpf_probe_read_str(&key.input, sizeof(key.input), (void *) PT_REGS_PARM1(ctx));
	val = counts.lookup_or_init(&key, &zero);
	(*val)++;
	return 0;
}

""" % (CURLOPT_URL)

b=BPF(text=prog)
b.attach_uprobe(name="curl", sym="curl_easy_setopt", fn_name="curl_easy_count")
b.attach_uprobe(name="c", sym="getnameinfo", fn_name="libc_getnameinfo_count")
b.attach_uprobe(name="c", sym="gethostbyname", fn_name="libc_gethostbyname_count")

while True:
	counts = b.get_table("counts")
	for k, v in counts.items():
   		print("%10d \"%s\"" % (v.value, k.input.decode("utf-8")))
	counts.clear()
	sleep(5)
