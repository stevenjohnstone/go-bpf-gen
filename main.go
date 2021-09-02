package main

import (
	"os"
	"path/filepath"
	"text/template"

	"github.com/stevenjohnstone/go-bpf-gen/ret"
)

const bpftraceSrc = `
uprobe:{{ .Exe }}:runtime.execute {
  // map thread id to goroutine id
  // first argument to runtime.execute is *g. Magic number 152 is offset of goroutine id
  // could be read from debug symbols?
  $gid = *(reg("ax") + 152);
  @gids[tid] = $gid;
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

func main() {
	tmpl := template.Must(template.New("bpf").Parse(bpftraceSrc))
	exe, err := filepath.Abs(os.Args[1])
	if err != nil {
		panic(err)
	}
	symbolName := os.Args[2]

	f, err := os.Open(exe)
	if err != nil {
		panic(err)
	}

	returns, err := ret.FindOffsets(f, symbolName)
	if err != nil {
		panic(err)
	}

	if err := tmpl.Execute(os.Stdout, struct {
		Exe     string
		Symbol  string
		Returns []int
	}{
		Exe:     exe,
		Symbol:  symbolName,
		Returns: returns,
	}); err != nil {
		panic(err)
	}
}
