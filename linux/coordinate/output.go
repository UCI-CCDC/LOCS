package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	. "github.com/logrusorgru/aurora"
)

type outputs struct {
	LoginOk bool
	Stdout  *strings.Builder
	Stderr  *strings.Builder
}

var (
	logger    *log.Logger
	tabs      string
	outputMap map[string]*outputs = make(map[string]*outputs)
	mapMtx    sync.Mutex
)

func InitLogger() {
	logger = log.New(os.Stdout, "", 0)
}

func Tabber(tabnum int) {
	tabs = ""
	for i := 0; i < tabnum; i++ {
		tabs += "\t"
	}
}

func Time() string {
	return time.Now().Format("03:04:05PM")
}

func getHost(i instance) *outputs {
	mapMtx.Lock()
	o, ok := outputMap[i.IP]
	if !ok {
		o = &outputs{
			Stdout:  new(strings.Builder),
			Stderr:  new(strings.Builder),
			LoginOk: true,
		}
		outputMap[i.IP] = o
	}
	mapMtx.Unlock()
	return o
}

func Stdout(i instance, a ...interface{}) {
	host := getHost(i)
	logger.Printf("%s%s:%s%s\n%s", tabs, BrightCyan("[STDOUT"), Summary(i), BrightCyan("]"), fmt.Sprintln(a...))
	for _, arg := range a {
		host.Stdout.WriteString(fmt.Sprintln(arg))
	}
}

func Stderr(i instance, a ...interface{}) {
	host := getHost(i)
	logger.Printf("%s%s:%s%s\n%s", tabs, BrightRed("[STDERR"), Summary(i), BrightRed("]"), fmt.Sprintln(a...))
	for _, arg := range a {
		host.Stderr.WriteString(fmt.Sprintln(arg))
	}
}

func LoginFailed(i instance) {
	ErrExtra(i, "Login failed!")
	host := getHost(i)
	host.LoginOk = false
}

func LoginOk(i instance) {
	host := getHost(i)
	host.LoginOk = true
}

func WriteJson(file *os.File) error {
	type jsonOutput struct {
		Stdout  string `json:"stdout"`
		Stderr  string `json:"stderr"`
		LoginOk bool   `json:"login_ok"`
	}
	jsonMap := make(map[string]jsonOutput)
	for ip, host := range outputMap {
		jsonMap[ip] = jsonOutput{
			Stdout:  host.Stdout.String(),
			Stderr:  host.Stderr.String(),
			LoginOk: host.LoginOk,
		}
	}
	bytes, err := json.MarshalIndent(jsonMap, "", "\t")
	if err != nil {
		return err
	}
	_, err = file.Write(bytes)
	return err
}

func Crit(i instance, a ...interface{}) {
	logger.Printf("%s%s:%s%s %s", tabs, Red("[CRIT"), Summary(i), Red("]"), fmt.Sprintln(a...))
}

func Err(a ...interface{}) {
	logger.Printf("%s%s %s", tabs, BrightRed("[ERROR]"), fmt.Sprintln(a...))
}

func ErrExtra(i instance, a ...interface{}) {
	logger.Printf("%s%s:%s%s %s", tabs, BrightRed("[ERROR"), Summary(i), BrightRed("]"), fmt.Sprintln(a...))
}

func Fatal(a ...interface{}) {
	logger.Printf("%s%s %s", tabs, BrightRed("[FATAL]"), fmt.Sprintln(a...))
	os.Exit(1)
}

func Warning(a ...interface{}) {
	logger.Printf("%s%s %s", tabs, Yellow("[WARN]"), fmt.Sprintln(a...))
}

func Info(a ...interface{}) {
	if !*quiet {
		logger.Printf("%s%s %s", tabs, BrightCyan("[INFO]"), fmt.Sprintln(a...))
	}
}

func InfoExtra(i instance, a ...interface{}) {
	if !*quiet {
		logger.Printf("%s%s:%s%s %s", tabs, BrightCyan("[INFO"), Summary(i), BrightCyan("]"), fmt.Sprintln(a...))
	}
}

func Debug(a ...interface{}) {
	if *debug {
		logger.Printf("%s%s %s", tabs, Cyan("[DEBUG]"), fmt.Sprintln(a...))
	}
}

func DebugExtra(i instance, a ...interface{}) {
	if *debug {
		logger.Printf("%s%s:%s%s %s", tabs, Cyan("[DEBUG"), Summary(i), Cyan("]"), fmt.Sprintln(a...))
	}
}

func Summary(i instance) string {
	if i.Script == "" {
		return fmt.Sprintf("%d:%s:%s", Blue(i.ID), BrightRed(i.Username), BrightGreen(i.IP))
	}
	return fmt.Sprintf("%d@%s:%s:%s/%s", Blue(i.ID), Time(), BrightRed(i.Username), BrightGreen(i.IP), BrightBlue(i.Script))
}
