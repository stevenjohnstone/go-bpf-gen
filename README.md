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
go-bpf-gen <template> <executable path> [key=value]

```

Example:

Let's instrument `dialTCP` in the `go` executable (it's written in go) using the builtin
`templates/latency.bt` template. Execute

```
go-bpf-gen templates/latency.bt $(which go) symbol='net.(*sysDialer).dialTCP' > test.bt
```
This gives a bpftrace script tailored to the target executable (in this case the go compiler):

```bpftrace
struct g {
	char _padding[152];
	int goid;
};

BEGIN {
  printf("Hit CTRL+C to end profiling\n");
}


uprobe:/usr/local/go/bin/go:runtime.execute {
	// map thread id to goroutine id
	$g = (struct g*)(reg("ax"));
	@gids[tid] = $g->goid;
}
END {
	clear(@gids);
}




uprobe:/usr/local/go/bin/go:"net.(*sysDialer).dialTCP" {
	$gid = @gids[tid];
	@start[$gid] = nsecs;
}


uprobe:/usr/local/go/bin/go:"net.(*sysDialer).dialTCP" + 83, 
uprobe:/usr/local/go/bin/go:"net.(*sysDialer).dialTCP" + 98 {
	$gid = @gids[tid];
	@durations = hist((nsecs - @start[$gid])/1000000);
	delete(@start[$gid]);
}

```

# Getting Symbol Names

Run ```readelf -a --wide target``` to get all the symbols in your target.

# Tracing Program In Docker Containers

Say that the target is /bin/foo in a container with pid 123. Use


```
/proc/123/root/bin/foo

```

as the target executable.

# Roll Your Own Templates

See the `templates` directory for examples on how to create templates. The syntax follow golang
[text templates](https://pkg.go.dev/text/template). The templates can make use of the following


* `.ExePath` gives the absolute path of the target executable
* `.GoRuntime.GoidOffset` gives the offset of the `goid` field in `runtime.g`. See templates/latency.bt for an example
* `.Arguments` gives access to the key-value pairs given on the command line



# Limitations

* Only works on x86-64
* Requires golang >= 1.17
* bpftrace needs to built with the option "ALLOW_UNSAFE_MODE" and bpftrace needs to be run with the "--unsafe" flag

# TODO

* Tutorial
* Examples of more complex scripts
