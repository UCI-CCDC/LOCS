package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	RANDSTRLEN = 12
)

var (
	rouletteRoll    int
	rouletteCounter int
)

func runner(ip string, usernameList, passwordList, keyList, environCmds []string, w *sync.WaitGroup) {
	defer w.Done()

	found := false
	var err error
	var sess *ssh.Session
	var wg sync.WaitGroup

	i := instance{
		IP: ip,
	}

	for _, u := range usernameList {
		if found {
			break
		}
		i.Username = u
		for _, k := range keyList {
			i.Key = k
			if *debug && *passwords != "" {
				InfoExtra(i, "Trying key '"+i.Key+"'")
			}
			sess, err = connect(i)
			if err == nil {
				InfoExtra(i, "Valid credentials for key", i.Key)
				found = true
				i.Username = u
				i.Key = k
				break
			}
		}
	}

	if !found {
		for _, u := range usernameList {
			if found {
				break
			}
			i.Username = u
			for _, p := range passwordList {
				i.Password = p
				if *debug && *passwords != "" {
					InfoExtra(i, "Trying password '"+i.Password+"'")
				}
				sess, err = connect(i)
				if err == nil {
					InfoExtra(i, "Valid credentials for", i.Username)
					found = true
					i.Username = u
					i.Password = p
					break
				}
			}
		}
	}

	if !found {
		LoginFailed(i)
		return
	}

	LoginOk(i)

	// Distribute files over X threads
	first := true
	scriptChan := make(chan string)
	exitChan := make(chan bool)

	for t := 0; t < *threads && t < len(scripts); t++ {
		if first {
			first = false
		}
		wg.Add(1)
		go ssher(i, sess, environCmds, scriptChan, exitChan, &wg)
		i.ID++
	}

	// Will send doneChan to kill watchdog.
	doneChan := make(chan bool)
	go watchdog(i, environCmds, scriptChan, exitChan, doneChan, &wg)

	for _, s := range scripts {
		scriptChan <- s
	}

	close(scriptChan)
	doneChan <- true

	wg.Wait()
}

// watchdog will see if connections die, and then spawns new ones.
func watchdog(i instance, environCmds []string, scriptChan chan string, exitChan, doneChan chan bool, wg *sync.WaitGroup) {
	for {
		select {
		case <-doneChan:
			DebugExtra(i, "Last script has been claimed, so watchdog is exiting.")
			return
		case <-exitChan:
			DebugExtra(i, "Watchdog saw that a session died! Starting up another...")
			sess, err := connect(i)
			if err != nil {
				Err("Login failed for known good creds! Have we been bamboozled? Error:", err)
				continue
			}
			wg.Add(1)
			go ssher(i, sess, environCmds, scriptChan, exitChan, wg)
			i.ID++
		}
	}
}

func keyboardInteractive(password string) ssh.KeyboardInteractiveChallenge {
	return func(user, instruction string, questions []string, echos []bool) ([]string, error) {
		// Just send the password back for all questions
		// (from terraform)
		answers := make([]string, len(questions))
		for i := range answers {
			answers[i] = string(password)
		}
		return answers, nil
	}
}

func connect(i instance) (*ssh.Session, error) {
	// SSH client config
	var config = &ssh.ClientConfig{}
	if i.Key != "" {
		key, err := os.ReadFile(i.Key)
		if err != nil {
			Fatal("Unable to read private key", err)
		}

		// Create the Signer for this private key.
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			log.Fatalf("unable to parse private key: %v", err)
		}

		config = &ssh.ClientConfig{
			User: i.Username,
			Auth: []ssh.AuthMethod{
				ssh.PublicKeys(signer),
			},
			Timeout: timeout,
			// We don't care about host key verification
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}

	} else {
		config = &ssh.ClientConfig{
			User: i.Username,
			Auth: []ssh.AuthMethod{
				ssh.Password(i.Password),
				ssh.KeyboardInteractive(keyboardInteractive(i.Password)),
			},
			Timeout: timeout,
			// We don't care about host key verification
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
	}

	// Connect to host
	DebugExtra(i, "Dialing", i.IP+":"+strconv.Itoa(*port)+"...")
	client, err := ssh.Dial("tcp", i.IP+":"+strconv.Itoa(*port), config)
	if err != nil {
		InfoExtra(i, "Login failed :(. Error:", err)
		return &ssh.Session{}, err
	} else {
		// Create sesssion
		sess, err := client.NewSession()
		if err != nil {
			Info("Session creation failed :(")
		} else {
			return sess, nil
		}
	}
	return nil, nil
}

func ssher(i instance, sess *ssh.Session, environCmds []string, scriptChan chan string, exitChan chan bool, wg *sync.WaitGroup) {
	defer func() {
		exitChan <- true
	}()
	defer sess.Close()
	defer wg.Done()

	// I/O for shell
	stdin, err := sess.StdinPipe()
	if err != nil {
		Err(err)
		return
	}

	var stdoutBytes bytes.Buffer
	var stderrBytes bytes.Buffer
	sess.Stdout = &stdoutBytes
	sess.Stderr = &stderrBytes

	var stdoutOffset int
	var stderrOffset int

	// Start remote shell
	err = sess.Shell()
	if err != nil {
		Err(err)
		return
	}

	index := 1
	escalated := false

	InfoExtra(i, "Interactive shell on", i.IP)

	if !*noValidate {
		if !validateShell(i, stdin, &stdoutBytes, stdoutOffset) {
			Crit(i, "Shell did not respond (to echo) before timeout!")
			return
		} else {
			DebugExtra(i, "Shell appears to be valid (echoes back successfully).")
		}
	}

	stdoutOffset = stdoutBytes.Len()
	stderrOffset = stderrBytes.Len()

	if i.Username != "root" {

		// If su is enabled, try to su to root.
		if *su != "" {
			fmt.Fprintf(stdin, "su -\n")
			time.Sleep(2 * time.Second)
			stderrOffset = stderrBytes.Len()
			DebugExtra(i, "Trying password", *su, "with su")
			fmt.Fprintf(stdin, "%s\n", *su)
			time.Sleep(4 * time.Second)
			if stderrBytes.Len()-stderrOffset > 0 {
				Stderr(i, strings.TrimSpace(stderrBytes.String()))
				Crit(i, "Failed to escalate from", i.Username, "to root (via su) on", i.IP)
				return
			} else {
				InfoExtra(i, "Successfully escalated to root (via su).")
				escalated = true
			}
		}

		// If sudo is enabled, and we're not already root, attempt to escalate.
		if *sudo && !escalated {
			fmt.Fprintf(stdin, "sudo -iS\necho\n")
			time.Sleep(2 * time.Second)
			// Password: prompt should be stderr even if no error is printed in time
			if stderrBytes.Len()-stderrOffset == 0 {
				InfoExtra(i, "Password-less sudo permitted, escalated to root.")
			} else {
				stderrOffset = stderrBytes.Len()
				fmt.Fprintf(stdin, "sudo -iS\n%s\n", i.Password)
				time.Sleep(4 * time.Second)
				if stderrBytes.Len()-stderrOffset > 0 {
					Stdout(i, strings.TrimSpace(stdoutBytes.String()))
					Stderr(i, strings.TrimSpace(stderrBytes.String()))
					Crit(i, "Failed to escalate from", i.Username, "to root (via sudo) on", i.IP)
					return
				}
				InfoExtra(i, "Successfully elevated to root (via sudo).")
			}
		}
	}

	for {
		script, ok := <-scriptChan
		if !ok {
			return
		}
		i.Script = script
		DebugExtra(i, "Running script:", script)

		// read file for module
		file, err := os.Open(script)
		if err != nil {
			Crit(i, errors.New("Error opening "+i.Script+": "+err.Error()))
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		scriptRan := true
		index = 0

		stdoutOffset = stdoutBytes.Len()
		stderrOffset = stderrBytes.Len()

		if len(environCmds) != 0 {
			for _, cmd := range environCmds {
				_, err = fmt.Fprintf(stdin, "%s\n", cmd)
				if err != nil {
					Crit(i, "Error submitting environmental command to stdin:", err)
					break
				}
			}
		}

		for scanner.Scan() {
			index++

			line, err := interpret(scanner.Text(), index, i)
			if err != nil {
				Crit(i, errors.New("Error: "+i.Script+": "+err.Error()))
				break
			}

			// If the input line is blank, or interpret returned an empty line,
			// move along
			if line == "" {
				continue
			}

			// Actually send the command to remote
			_, err = fmt.Fprintf(stdin, "%s\n", line)
			if err != nil {
				Crit(i, "Error submitting line to stdin:", err)
				break
			}

		}

		var randOffset int

		if *noValidate {
			// When we're not validating that a script finishes, just wait for
			// half of the timeout and hope for the best
			DebugExtra(i, "Waiting timeout/2 for script to finish.")
			time.Sleep(timeout / 2)
		} else {
			scriptRan := validateShell(i, stdin, &stdoutBytes, stdoutOffset)
			if !scriptRan {
				Crit(i, "Script didn't finish before timeout! Killing this session...")
			} else {
				InfoExtra(i, "Finished running script!")
				// Add one for the newline
				randOffset = RANDSTRLEN + 1
			}
		}

		if !*errs {
			if stdoutBytes.Len()-stdoutOffset-randOffset > 0 {
				if strings.TrimSpace(stdoutBytes.String()) != "" {
					Stdout(i, strings.TrimSpace(stdoutBytes.String()[stdoutOffset:stdoutBytes.Len()-randOffset]))
				}
			}
		}

		if stderrBytes.Len()-stderrOffset > 0 {
			Stderr(i, strings.TrimSpace(stderrBytes.String()[stderrOffset:]))
		}

		if err := scanner.Err(); err != nil {
			Crit(i, errors.New("scanner error: "+err.Error()))
		}

		if !scriptRan {
			return
		}
	}

	_, err = fmt.Fprintf(stdin, "logout\n")
	if err != nil {
		Crit(i, errors.New("Error submitting logout command: "+err.Error()))
	}

	if escalated {
		_, err = fmt.Fprintf(stdin, "logout\n")
		if err != nil {
			Crit(i, errors.New("Error submitting second logout command: "+err.Error()))
		}
	}

	// Wait for sess to finish with timeout
	errChan := make(chan error)
	go func() {
		errChan <- sess.Wait()
	}()

	select {
	case <-errChan:
	case <-time.After(timeout):
		Err("Shell close wait timed out. Leaving session.")
	}
}

func lineError(s string, lineNum int, line string, err string) error {
	return errors.New(s + ": " + "line " + strconv.Itoa(lineNum) + ": " + err + ": " + line)
}

func interpret(line string, lineNum int, i instance) (string, error) {
	if !*doInterpret {
		return line, nil
	}
	line = strings.TrimSpace(line)
	if len(line) == 0 {
		return "", nil
	}

	// #CALLBACK_IP directive
	if strings.Contains(line, "#CALLBACK_IP") {
		if len(callbackIPs) > 0 {
			callBack := callbackIPs[rand.Intn(len(callbackIPs))]
			line = strings.Replace(line, "#CALLBACK_IP", callBack, -1)
		} else {
			ErrExtra(i, "Script wants a callback IP, but no callbacks specified!")
		}
	}

	// #DROP directive
	if len(line) >= 5 && strings.Contains(line[:5], "#DROP") {
		splitLine := strings.Split(line, " ")
		if len(splitLine) != 3 {
			return "", lineError(i.Script, lineNum, line, "malformed drop")
		}

		// TODO do this intelligently
		fileName := splitLine[1]
		if len(fileName) > 0 && fileName[0] != '/' {
			filePath := strings.Split(i.Script, "/")
			if len(filePath) > 1 {
				filePathStr := strings.Join(filePath[:len(filePath)-1], "/")
				fileName = filePathStr + "/" + fileName
			}
		}

		if *debug {
			InfoExtra(i, "(line "+strconv.Itoa(lineNum)+")", "Dropping "+fileName)
		}

		fileContent, err := os.ReadFile(fileName)
		if err != nil {
			return "", lineError(i.Script, lineNum, line, "invalid file specified to drop at "+splitLine[1])
		}

		// TODO: if buffer is too large, reset it and offset
		// base64 encode file contents
		encoded := base64.StdEncoding.EncodeToString([]byte(fileContent))
		return fmt.Sprintf("echo '%s' | base64 -d > %s", encoded, splitLine[2]), nil
	}

	if *debug {
		InfoExtra(i, "(line "+strconv.Itoa(lineNum)+")", line)
	}

	return line, nil
}

func waitOutput(output *bytes.Buffer, offset int, randStr string) bool {
	for t := 0; t*int(shortTimeout) < int(timeout); t++ {
		if output.Len()-offset >= len(randStr)+1 {
			if strings.Contains(strings.TrimSpace(output.String()[output.Len()-len(randStr)-1:]), randStr) {
				return true
			}
		}
		time.Sleep(shortTimeout)
	}
	return false
}

func validateShell(i instance, stdin io.Writer, output *bytes.Buffer, offset int) bool {
	randStr := randomString(RANDSTRLEN)
	_, err := fmt.Fprintf(stdin, "echo %s\n", randStr)
	if err != nil {
		Crit(i, "Error submitting start validation line to stdin:", err)
		return false
	}
	return waitOutput(output, offset, randStr)
}

func randomString(n int) string {
	var letters = []rune("abcfgikmoqsuvwyABDFHJLMNPRTUWY024579")
	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}
