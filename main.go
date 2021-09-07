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
	"github.com/stevenjohnstone/go-bpf-gen/ret"
)

//go:embed templates
var templates embed.FS

type Target struct {
	ExePath   string
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

func (t Target) SymbolReturnsNoFail(symbol string) []int {
	v, err := t.SymbolReturns(symbol)
	if err != nil {
		return []int{1}
	}
	return v
}

func regsabi(exe string) (bool, error) {
	f, err := os.Open(exe)
	if err != nil {
		return false, err
	}
	defer f.Close()
	return abi.Regs(f)
}

var regs = [...]string{"ax", "bx", "cx", "di", "si", "r8", "r9", "r10", "r11"}

// Arg maps argument indices to bpftrace built-ins taking into account which ABI
// is in use
func (t Target) Arg(i int) string {
	if t.RegsABI {
		// rax, rbx, rcx, rdi, rsi, r8, r9, r10, r11 should do
		if i < 0 || i >= len(regs) {
			panic("argument out of bounds. roll your own")
		}
		return fmt.Sprintf("reg(\"%s\")", regs[i])
	}

	return fmt.Sprintf("sarg%d", i)
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

	regsAbi, err := regsabi(exe)
	if err != nil {
		log.Printf("couldn't get regs abi (%s). falling back to stack calling convention", err)
	}

	return &Target{
		ExePath:   exe,
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

	tmpl := template.Must(template.New("bpf").Funcs(template.FuncMap{"panic": func(s string) string { panic(s) }}).Parse(string(scriptTemplate)))
	if err := tmpl.Execute(os.Stdout, target); err != nil {
		log.Fatalf("failed to process template: %s", err)
	}
}
