# About

Generate bpftrace programs suitable for tracing a golang program on x86-64 with
golang >= 1.17.

# Why?

Using bpftrace with golang isn't as straightforward as for C/C++ compiled code. See
this [blog](https://www.brendangregg.com/blog/2017-01-31/golang-bcc-bpf-function-tracing.html)
post by Brendan Gregg.

## Problem 1: Stacks can grow and be copied

uretprobes are implemented by hijacking return addresses on the stack. Golang can grow
stacks and in doing so move the stack contents. This can result in golang panics when being
traced. To get around this, the template generator looks for the addresses of RET instructions
in the targeted function and creates uprobes for those.

## Problem 2: Goroutines don't map 1-1 with system threads

It's not a problem for golang but it's a problem when trying to do per-thread statistics
with bpftrace. A goroutine may move around system threads so we need a way to map goroutine
IDs to thread IDs.



# Build & Install

```
go install github.com/stevenjohnstone/go-bpf-gen@latest

```

# Usage


```
go-bpf-gen <executable path> <symbol>

```
to generate a template file to stdout.

Example:

```
go-bpf-gen $(which go) 'strings.(*Replacer).build' > test.bt
```

generates a bpftrace program on my system like this:

```bpftrace

uprobe:/usr/local/go/bin/go:runtime.execute {
  // map thread id to goroutine id
  // first argument to runtime.execute is *g. Magic number 152 is offset of goroutine id
  // could be read from debug symbols?
  $gid = *(reg("ax") + 152);
  @gids[tid] = $gid;
}

uprobe:/usr/local/go/bin/go:"net.(*sysDialer).dialTCP" {
	$gid = @gids[tid];
	@start[$gid] = nsecs;
}


uprobe:/usr/local/go/bin/go:"net.(*sysDialer).dialTCP" + 83 {
	$gid = @gids[tid];
	@durations = hist(nsecs - @start[$gid]);
	delete(@start[$gid]);
}

uprobe:/usr/local/go/bin/go:"net.(*sysDialer).dialTCP" + 98 {
	$gid = @gids[tid];
	@durations = hist(nsecs - @start[$gid]);
	delete(@start[$gid]);
}
```

This bpftrace program can be used to profile time spent in ```dialTCP``` by, say,
```go get github.com/stevenjohnstone/go-bpf-gen```.

The script can be used as a starting point for more complex scripts.


# Getting Symbol Names

Run ```readelf -a --wide target``` to get all the symbols in your target.

# Limitations

* Only works on x86-64
* Requires golang >= 1.17
* bpftrace needs to built with the option "ALLOW_UNSAFE_MODE" and bpftrace needs to be run with the "--unsafe" flag

# TODO

* Tutorial
* Examples of more complex scripts
