package main

import (
	"embed"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/stevenjohnstone/go-bpf-gen/abi"
	"github.com/stevenjohnstone/go-bpf-gen/goid"
	"github.com/stevenjohnstone/go-bpf-gen/ret"
)

//go:embed templates
var templates embed.FS

type GoRuntime struct {
	GoidOffset int64
}

type Target struct {
	ExePath   string
	GoRuntime GoRuntime
	Arguments func(string) []string
	RegsABI   bool
	offsets   map[string][]int
}

func (t Target) SymbolReturns(symbol string) ([]int, error) {
	v, ok := t.offsets[symbol]
	if ok {
		return v, nil
	}
	f, err := os.Open(t.ExePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	offsets, err := ret.FindOffsets(f, symbol)
	if err != nil {
		return nil, err
	}
	t.offsets[symbol] = offsets
	return offsets, nil
}

func regsabi(exe string) (bool, error) {
	f, err := os.Open(exe)
	if err != nil {
		return false, err
	}
	defer f.Close()
	return abi.Regs(f)
}

func NewTarget(exe string, arguments func(string) []string) (*Target, error) {
	exe, err := filepath.Abs(exe)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(exe)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	goid, err := goid.Offset(f)
	if err != nil {
		return nil, err
	}

	regsAbi, err := regsabi(exe)
	if err != nil {
		return nil, err
	}

	return &Target{
		ExePath: exe,
		GoRuntime: GoRuntime{
			GoidOffset: goid,
		},
		Arguments: arguments,
		RegsABI:   regsAbi,
		offsets:   map[string][]int{},
	}, nil
}

func parseArguments(args []string) (scriptFile, targetExe string, kv map[string][]string, err error) {
	kv = map[string][]string{}
	if len(args) < 3 {
		err = fmt.Errorf("usage %s <template file> <target file>", args[0])
		return
	}
	scriptFile, targetExe = args[1], args[2]

	args = args[3:]

	for _, arg := range args {
		s := strings.Split(arg, "=")
		if len(s) != 2 {
			err = fmt.Errorf("malformed argument %s, must be of form key=value", arg)
			return
		}
		k, v := s[0], s[1]
		kv[k] = append(kv[k], v)
	}
	return
}

func main() {

	scriptFile, targetExe, kv, err := parseArguments(os.Args)
	if err != nil {
		log.Fatal(err)
	}

	scriptTemplate, err := ioutil.ReadFile(scriptFile)
	if err != nil {
		// try embedded files
		f, err1 := templates.Open(scriptFile)
		if err1 != nil {
			log.Fatalf("failed to open %s on filesystem: (%s), tried embedded files got %s", scriptFile, err, err1)
		}
		scriptTemplate, err = ioutil.ReadAll(f)
		if err != nil {
			panic(err)
		}
	}

	target, err := NewTarget(targetExe, func(key string) []string {
		return kv[key]
	})

	if err != nil {
		log.Fatalf("failed to process target: %s", err)
	}

	tmpl := template.Must(template.New("bpf").Parse(string(scriptTemplate)))
	if err := tmpl.Execute(os.Stdout, target); err != nil {
		log.Fatalf("failed to process template: %s", err)
	}
}
