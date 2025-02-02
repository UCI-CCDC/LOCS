package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"go4.org/netipx"
	"golang.org/x/term"
	"net/netip"

	"encoding/json"
	flag "github.com/spf13/pflag"
)

type instance struct {
	ID       int
	IP       string
	Username string
	Password string
	Key      string
	Script   string
	Port     int
}

type jsonEntry struct {
	User     string   `json:"user"`
	Password string   `json:"password"`
	Port     int      `json:"port"`
	Env      []string `json:"env"`
}

type Script struct {
	Name          string
	IfState       int
	RouletteState int
	OutputState   int
}

var (
	timeout      time.Duration
	shortTimeout time.Duration
)

var (
	port        = flag.IntP("port", "P", 22, "SSH port to use")
	threads     = flag.IntP("limit", "l", 3, "Thread limit per IP")
	timelimit   = flag.IntP("timeout", "T", 30, "Time limit per script")
	targets     = flag.StringSliceP("targets", "t", []string{""}, "Comma-separated list of targets in the form <user:pass@ip:port(args)> (ex., 127.0.0.1-127.0.0.5,192.168.1.0/24)")
	usernames   = flag.StringP("usernames", "u", "", "List of usernames")
	passwords   = flag.StringP("passwords", "p", "", "List of passwords")
	callbacks   = flag.StringP("callbacks", "c", "", "Callback IP address(es)")
	keys        = flag.StringP("keys", "k", "", "SSH key to use when connection")
	su          = flag.StringP("su", "R", "", "Attempt to su to root with this password, if not root")
	environment = flag.StringP("env", "E", "", "Set these variables before running scripts")
	sudo        = flag.BoolP("sudo", "S", false, "Attempt to escalate through sudo, if not root")
	quiet       = flag.BoolP("quiet", "q", false, "Print only script output")
	debug       = flag.BoolP("debug", "d", false, "Print debug messages")
	yes         = flag.BoolP("yes", "y", false, "Always be yessing")
	errs        = flag.BoolP("errors", "e", false, "Print errors only (no stdout)")
	noValidate  = flag.BoolP("no-validate", "n", false, "Don't ensure shell is valid, or that scripts have finished running")
	output      = flag.StringP("output", "O", "output.json", "Location to write stdout and stderr of each script")
	jsonIn      = flag.StringP("json", "j", "", "Use JSON format to specify what to run on each host. Ignores other command line arguments. (ex. {\"10.100.3.88\":{\"user\":\"root\",\"password\":\"CMpass123!\",\"port\":22,\"env\":[\"A=2\",\"B=3\",\"C=4\"]}})")
	doInterpret = flag.BoolP("interpret", "i", false, "Interpret coordinate directives")
	callbackIPs = []string{}
	scripts     = []string{}
	addresses   = []netip.Addr{}
)

func main() {
	InitLogger()
	flag.Parse()

	// Set timeouts
	timeout = time.Duration(*timelimit * int(time.Second))
	shortTimeout = time.Duration(*timelimit * 40 * int(time.Millisecond))

	// Fetch scripts
	scripts = flag.Args()
	if (*jsonIn == "" || len(scripts) == 0) && ((len(*targets) == 1 && (*targets)[0] == "") || len(scripts) == 0 || *usernames == "") {
		Err("Missing target(s), script(s), and/or username(s).")
		fmt.Println("Usage:")
		flag.PrintDefaults()
		return
	}

	// Ensure we can make the output file before running so we don't discard correct output if it ran fine
	file, err := os.Create(*output)
	if err != nil {
		Fatal("Couldn't create output file", err)
	}

	if *jsonIn != "" {
		jsonObj := make(map[string]jsonEntry)
		if err := json.Unmarshal([]byte(*jsonIn), &jsonObj); err != nil {
			Fatal("Couldn't unmarshal json input", err)
		}
		// Distribute IPs to runner tasks
		tid := 0
		var wg sync.WaitGroup
		for ip, data := range jsonObj {
			tid++
			wg.Add(1)
			go runner(ip, []string{data.User}, []string{data.Password}, []string{}, data.Env, &wg)
		}
		wg.Wait()
	} else {
		var (
			keyList      = []string{}
			usernameList = []string{}
			passwordList = []string{}
			environCmds  = []string{}
		)
		// Parse IP addresses
		hostnames := []string{}
		targetTokens := []string{}
		for _, t := range *targets {
			targetTokens = append(targetTokens, strings.Split(t, ",")...)
		}
		ipSetBuilder := netipx.IPSetBuilder{}
		for _, t := range targetTokens {
			if i := strings.IndexByte(t, '-'); i != -1 {
				ips, err := netipx.ParseIPRange(t)
				if err != nil {
					Fatal(err)
				}
				ipSetBuilder.AddRange(ips)
			} else if i := strings.IndexByte(t, '/'); i != -1 {
				pf, err := netip.ParsePrefix(t)
				if err != nil {
					Fatal(err)
				}
				ipSetBuilder.AddRange(netipx.RangeOfPrefix(pf))
			} else {
				ip, err := netip.ParseAddr(t)
				if err != nil {
					Debug("Invalid IP address, assuming it's a hostname:", t)
					hostnames = append(hostnames, t)
				} else {
					ipSetBuilder.Add(ip)
				}
			}
		}

		ipSet, err := ipSetBuilder.IPSet()
		if err != nil {
			Fatal(err)
		}

		stringAddresses := []string{}
		for _, r := range ipSet.Ranges() {
			if r.From().Compare(r.To()) != 0 {
				stringAddresses = append(stringAddresses, r.String())
			} else {
				stringAddresses = append(stringAddresses, r.From().String())
			}
			ip := r.From()
			for ip.Compare(r.To().Next()) != 0 {
				addresses = append(addresses, ip)
				ip = ip.Next()
			}
		}

		if *environment != "" {
			environCmds = strings.Split(*environment, ",")
		}

		if !*quiet || !*yes {
			hostnameSpacing := "\n\t"
			if len(hostnames) == 0 {
				hostnameSpacing = ""
			}
			stringAddressesSpacing := "\n\t"
			if len(stringAddresses) == 0 {
				stringAddressesSpacing = ""
			}
			fmt.Printf("Specified targets (%d addresses, %d hostnames):%s%s%s%s\n", len(addresses), len(hostnames), hostnameSpacing, strings.Join(hostnames, "\n\t"), stringAddressesSpacing, strings.Join(stringAddresses, "\n\t"))
			fmt.Printf("Specified scripts (%d files):\n\t%s\n", len(scripts), strings.Join(scripts, "\n\t"))
			if len(environCmds) != 0 {
				fmt.Printf("Specified environmental commands (%d items):\n\t%s\n", len(environCmds), strings.Join(environCmds, "\n\t"))
			}
		}

		if !*yes {
			reader := bufio.NewReader(os.Stdin)
			fmt.Printf("Use The Coordinate? [y/n]: ")
			response, err := reader.ReadString('\n')
			if err != nil {
				Fatal(err)
			}
			response = strings.ToLower(strings.TrimSpace(response))
			if response != "y" && response != "yes" {
				os.Exit(1)
			}
		}

		// If callback IP(s), split them
		if *callbacks != "" {
			callbackIPs = strings.Split(*callbacks, ",")
		}

		// Split usernames
		usernameList = strings.Split(*usernames, ",")
		if *passwords == "" && *keys == "" {
			fmt.Print("Password: ")
			password, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				Fatal(err)
			}
			passwordList = []string{strings.TrimSpace(string(password))}
			fmt.Println()
		} else {
			passwordList = strings.Split(*passwords, ",")
		}

		// Split keys
		if *keys != "" {
			keyList = strings.Split(*keys, ",")
		}

		// Distribute IPs to runner tasks
		tid := 0
		var wg sync.WaitGroup
		for _, ip := range addresses {
			tid++
			wg.Add(1)
			go runner(ip.String(), usernameList, passwordList, keyList, environCmds, &wg)
		}

		for _, host := range hostnames {
			tid++
			wg.Add(1)
			go runner(host, usernameList, passwordList, keyList, environCmds, &wg)
		}

		wg.Wait()
	}

	err = WriteJson(file)
	if err != nil {
		Err("Couldn't write script output to file", err)
	}
}
