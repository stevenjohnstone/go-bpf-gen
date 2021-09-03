package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"
	"text/template"

	"github.com/stevenjohnstone/go-bpf-gen/goid"
	"github.com/stevenjohnstone/go-bpf-gen/ret"
)

const (
	bpftraceEmptySrc = `
// entry to {{ $.Symbol }}
uprobe:{{ .Exe }}:"{{ .Symbol }}" {
}

{{ range $r := .Returns }}
// exit from {{ $.Symbol }}
uprobe:{{ $.Exe }}:"{{ $.Symbol }}" + {{ $r }} {
}
{{ end }}`

	bpftraceProfileSrc = `

struct g {
	char _padding[{{ .GoidOffset }}];
	int goid;
};

uprobe:{{ .Exe }}:runtime.execute {
	// map thread id to goroutine id
	$g = (struct g*)(reg("ax"));
	@gids[tid] = $g->goid;
}
END {
	clear(@gids);
}

uprobe:{{ .Exe }}:"{{ .Symbol }}" {
	$gid = @gids[tid];
	@start[$gid] = nsecs;
}

{{ range $r := .Returns }}
uprobe:{{ $.Exe }}:"{{ $.Symbol }}" + {{ $r }} {
	$gid = @gids[tid];
	@durations = hist((nsecs - @start[$gid])/1000000);
	delete(@start[$gid]);
}
{{ end }}`

	goidOffsetMagicFallback int64 = 152
)

func main() {

	empty := flag.Bool("empty", false, "output a template bpftrace program with no function contents")
	flag.Parse()

	args := flag.Args()
	if len(args) != 2 {
		log.Fatalf("usage: %s [--empty] <target executable> <symbol name>", os.Args[0])
	}

	exe, symbolName := args[0], args[1]

	src := bpftraceProfileSrc
	if *empty {
		src = bpftraceEmptySrc
	}

	tmpl := template.Must(template.New("bpf").Parse(src))
	exe, err := filepath.Abs(exe)
	if err != nil {
		panic(err)
	}

	f, err := os.Open(exe)
	if err != nil {
		panic(err)
	}

	returns, err := ret.FindOffsets(f, symbolName)
	if err != nil {
		panic(err)
	}

	if _, err := f.Seek(0, 0); err != nil {
		panic(err)
	}

	goidOffset, err := goid.Offset(f)
	if err != nil {
		log.Printf("failed to find goid offset (%s). Falling back to %d\n", err, goidOffsetMagicFallback)
		goidOffset = goidOffsetMagicFallback
	}

	if err := tmpl.Execute(os.Stdout, struct {
		Exe        string
		Symbol     string
		GoidOffset int64
		Returns    []int
	}{
		Exe:        exe,
		Symbol:     symbolName,
		GoidOffset: goidOffset,
		Returns:    returns,
	}); err != nil {
		panic(err)
	}
}
