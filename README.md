# About

Generate bpftrace programs suitable for tracing a golang program on x86-64.

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

# Solution

This program can generate bpftrace programs from templates, filling in details like the
location of RET instructions, offsets of goroutine ID values in structures etc.

# Bundled Scripts

## goroutine.bt
The script generated by

```
go-bpf-gen templates/goroutine.bt <target binary>
```
prints a message whenever a goroutine is spawned.

## httpsnoop.bt
The script generated by

```
go-bpf-gen templates/httpsnoop.bt <target binary>
```
tracks outgoing HTTP requests.

## latency.bt

The script generated by
```
go-bpf-gen templates/latency.bt <target binary> symbol='<symbol name>' [symbol='<symbol name>']

```

will measure the time spent in functions specified in the `symbol` parameters.

## recover.bt

The script generated by
```
go-bpf-gen templates/recover.bt <target binary>

```
will record stack traces from calls to `recover()` after a panic.

## shortread.bt
The script generated by
```
go-bpf-gen templates/shortread.bt <target binary>
```
will record stack traces from calls to [`func(f *os.File) Read([]byte) (int, error)`](https://pkg.go.dev/os#File.Read) which read fewer bytes than the length of the input buffer. This is a [common
programming mistake](https://github.com/golang/go/issues/48182) in golang.

## skeleton.bt
The script generated by
```
go-bpf-gen templates/shortread.bt <target binary> symbol='<symbol name>' [symbol='<symbol name>']
```
has empty `uprobe` functions which trace the entry and exit points of
the functions with specified symbols.

## tcpremote.bt
The script generated by
```
go-bpf-gen templates/tcpremote.bt <target binary>

```
will output address and port for remote servers to which the program makes connections.

## tlssecrets.bt
The script generated by
```
go-bpf-gen templates/tlssecrets.bt <target binary>

```
will output secrets which can be used with wireshark to decode
network traces of TLS connections made to/from the program.






# Build & Install

```
go install github.com/stevenjohnstone/go-bpf-gen@latest

```

# Usage


```
go-bpf-gen <template> <executable path> [key=value]

```

Example:

Let's find who dockerd makes connections to when we do a `docker pull`.
We generate a bpftrace script to instrument the `dockerd` executable (it's written in go) using the builtin
`templates/httpsnoop.bt` template. Execute

```
go-bpf-gen templates/httpsnoop.bt $(which dockerd) > dockerd.bt
```
This gives a bpftrace script tailored to the target executable

```bpftrace
struct url {
  uint8_t *scheme;
  int schemelen;
  uint8_t *opaque;
  int opaquelen;
  uint64_t pad;
  uint8_t *host;
  int hostlen;
  uint8_t *path;
  int pathlen;
};

struct request {
  uint8_t pad[16];
  struct url *url;
};

struct response {
  uint8_t *statusstr;
  uint8_t *statusstrlen;
  int statuscode;
};


uprobe:/usr/bin/dockerd:runtime.execute {
	// map thread id to goroutine id
	@gids[tid] = sarg0
}

tracepoint:sched:sched_process_exit {
  delete(@rscheme[@gids[tid]]);
  delete(@rhost[@gids[tid]]);
  delete(@rpath[@gids[tid]]);
  delete(@gids[tid]);
}


uprobe:/usr/bin/dockerd:"net/http.(*Client).do" {
  $url = ((struct request *)sarg1)->url;
  $scheme = str($url->scheme, $url->schemelen);
  $host = str($url->host, $url->hostlen);
  $path = str($url->path, $url->pathlen);

  @rscheme[@gids[tid]] = $scheme;
  @rhost[@gids[tid]] = $host;
  @rpath[@gids[tid]] = $path;
}


uprobe:/usr/bin/dockerd:"net/http.(*Client).do" + 364, 
uprobe:/usr/bin/dockerd:"net/http.(*Client).do" + 1225, 
uprobe:/usr/bin/dockerd:"net/http.(*Client).do" + 1394, 
uprobe:/usr/bin/dockerd:"net/http.(*Client).do" + 2822, 
uprobe:/usr/bin/dockerd:"net/http.(*Client).do" + 2965, 
uprobe:/usr/bin/dockerd:"net/http.(*Client).do" + 3456, 
uprobe:/usr/bin/dockerd:"net/http.(*Client).do" + 4134, 
uprobe:/usr/bin/dockerd:"net/http.(*Client).do" + 4387, 
uprobe:/usr/bin/dockerd:"net/http.(*Client).do" + 4511 {
  $resp = (struct response *)reg("ax"); // XXXSJJ: rax contains pointer to the response
  if ($resp == 0) {
    printf("error %s://%s%s\n", @rscheme[@gids[tid]], @rhost[@gids[tid]], @rpath[@gids[tid]]);
  } else {
    printf("%d: %s://%s%s\n", $resp->statuscode, @rscheme[@gids[tid]], @rhost[@gids[tid]], @rpath[@gids[tid]]);
  }
  print(ustack());
}

```

When I execute `docker pull alpine` on my system, the above script outputs

```
Attaching 12 probes...
401: https://registry-1.docker.io/v2/

        net/http.(*Client).do+1225
        local.github.com/docker/docker/distribution.NewV2Repository+627
        github.com/docker/docker/distribution.(*v2Puller).Pull+270
        github.com/docker/docker/distribution.Pull+1525
        github.com/docker/docker/daemon/images.(*ImageService).pullImageWithReference+1345
        github.com/docker/docker/daemon/images.(*ImageService).PullImage+350
        local.github.com/docker/docker/api/server/router/image.(*imageRouter).postImagesCreate+1666
        github.com/docker/docker/api/server/router/image.(*imageRouter).postImagesCreate-fm+107
        github.com/docker/docker/api/server/middleware.ExperimentalMiddleware.WrapHandler.func1+375
        local.github.com/docker/docker/api/server/middleware.VersionMiddleware.WrapHandler.func1+1531
        github.com/docker/docker/pkg/authorization.(*Middleware).WrapHandler.func1+2086
        local.github.com/docker/docker/api/server.(*Server).makeHTTPHandler.func1+577
        net/http.HandlerFunc.ServeHTTP+70
        github.com/docker/docker/vendor/github.com/gorilla/mux.(*Router).ServeHTTP+228
        net/http.serverHandler.ServeHTTP+166
        net/http.(*conn).serve+2167
        runtime.goexit+1

200: https://auth.docker.io/token

        net/http.(*Client).do+1225
        github.com/docker/docker/vendor/github.com/docker/distribution/registry/client/auth.(*tokenHandler).fetchToken+710
        local.github.com/docker/docker/vendor/github.com/docker/distribution/registry/client/auth.(*tokenHandler).getToken+859
        github.com/docker/docker/vendor/github.com/docker/distribution/registry/client/auth.(*tokenHandler).AuthorizeRequest+146
        github.com/docker/docker/vendor/github.com/docker/distribution/registry/client/auth.(*endpointAuthorizer).ModifyRequest+793
        github.com/docker/docker/vendor/github.com/docker/distribution/registry/client/transport.(*transport).RoundTrip+137
        local.net/http.send+1093
        local.net/http.(*Client).send+252
        net/http.(*Client).do+976
        github.com/docker/docker/vendor/github.com/docker/distribution/registry/client.(*tags).Get.func1+451
        local.github.com/docker/docker/vendor/github.com/docker/distribution/registry/client.(*tags).Get+395
        github.com/docker/docker/distribution.(*v2Puller).pullV2Tag+6799
        github.com/docker/docker/distribution.(*v2Puller).pullV2Repository+889
        github.com/docker/docker/distribution.(*v2Puller).Pull+784
        github.com/docker/docker/distribution.Pull+1525
        github.com/docker/docker/daemon/images.(*ImageService).pullImageWithReference+1345
        github.com/docker/docker/daemon/images.(*ImageService).PullImage+350
        local.github.com/docker/docker/api/server/router/image.(*imageRouter).postImagesCreate+1666
        github.com/docker/docker/api/server/router/image.(*imageRouter).postImagesCreate-fm+107
        github.com/docker/docker/api/server/middleware.ExperimentalMiddleware.WrapHandler.func1+375
        local.github.com/docker/docker/api/server/middleware.VersionMiddleware.WrapHandler.func1+1531
        github.com/docker/docker/pkg/authorization.(*Middleware).WrapHandler.func1+2086
        local.github.com/docker/docker/api/server.(*Server).makeHTTPHandler.func1+577
        net/http.HandlerFunc.ServeHTTP+70
        github.com/docker/docker/vendor/github.com/gorilla/mux.(*Router).ServeHTTP+228
        net/http.serverHandler.ServeHTTP+166
        net/http.(*conn).serve+2167
        runtime.goexit+1

200: https://auth.docker.io/token

        net/http.(*Client).do+1225
        local.github.com/docker/docker/vendor/github.com/docker/distribution/registry/client.(*tags).Get+395
        github.com/docker/docker/distribution.(*v2Puller).pullV2Tag+6799
        github.com/docker/docker/distribution.(*v2Puller).pullV2Repository+889
        github.com/docker/docker/distribution.(*v2Puller).Pull+784
        github.com/docker/docker/distribution.Pull+1525
        github.com/docker/docker/daemon/images.(*ImageService).pullImageWithReference+1345
        github.com/docker/docker/daemon/images.(*ImageService).PullImage+350
        local.github.com/docker/docker/api/server/router/image.(*imageRouter).postImagesCreate+1666
        github.com/docker/docker/api/server/router/image.(*imageRouter).postImagesCreate-fm+107
        github.com/docker/docker/api/server/middleware.ExperimentalMiddleware.WrapHandler.func1+375
        local.github.com/docker/docker/api/server/middleware.VersionMiddleware.WrapHandler.func1+1531
        github.com/docker/docker/pkg/authorization.(*Middleware).WrapHandler.func1+2086
        local.github.com/docker/docker/api/server.(*Server).makeHTTPHandler.func1+577
        net/http.HandlerFunc.ServeHTTP+70
        github.com/docker/docker/vendor/github.com/gorilla/mux.(*Router).ServeHTTP+228
        net/http.serverHandler.ServeHTTP+166
        net/http.(*conn).serve+2167
        runtime.goexit+1
```

# Getting Symbol Names

Run ```readelf -a --wide target``` to get all the symbols in your target.

# Tracing Programs In Docker Containers

Say that the target is /bin/foo in a container with pid 123. Use


```
/proc/123/root/bin/foo

```

as the target executable.

# Roll Your Own Templates

See the `templates` directory for examples on how to create templates. These are golang
[text templates](https://pkg.go.dev/text/template). The templates can make use of the following


* `.ExePath` gives the absolute path of the target executable
* `.Arguments` gives access to the key-value pairs given on the command line
* `.RegsABI` is true if argument passing with registers is enabled



# Limitations

* Only works on x86-64
* Requires target to be built with golang >= 1.17 for full functionality. Some scripts will not work without the register based calling convention.
* short lived programs may have stack traces which are only hex addresses. See [this](https://github.com/iovisor/bpftrace/issues/246) bug
* https://github.com/iovisor/bpftrace/issues/2388 prevents scripts working with v0.16.0. Build a static bpftrace with a fix using [hacks/build-bpftrace.sh](hacks/build-bpftrace.sh)

# TODO

* Tutorial
* Examples of more complex scripts
