all:
	clang -O2 -S -Wall -C11 -target bpf -c bpf.c -o bpf.o
