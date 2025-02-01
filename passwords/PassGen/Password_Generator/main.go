package main

import (
	"atoll"
	"bufio"
	"crypto/sha256"
	"encoding/csv"
	"fmt"
	"golang.org/x/term"
	"log"
	"os"
	"regexp"
	"strconv"
	"syscall"
	"unicode"
)

var HELP = `
Password Generator: 
Modified version of atoll
Written by Payton Erickson

-l   [int]  Number of characters in the password or words in the passphrase (default: 8)
-n   [int]  Number of passwords/passphrases to generate in a batch process (default: 1)
-csv [str]  The name of the csv file that will be outputted (default: print to screen)

Passphrases only:
-p          Enables passphrase mode (default: false)
-s   [char] The separator between words (only applies to passphrases) (default: ' ')
-w   [str]  The name of a custom txt diceware wordlist (must have the dice format before first word. Ex: 1111 word) (default: Built-in)
-wl         Enable the default WordList (word word word)
-wlc        Enable WordList with Capitals (Word Word Word)
-wln        Enable WordList with a random number appended to a random word (word1 word word)
-wlnc       Enable WordList with Caps and Numbers (Word Word5 Word)

Passwords only:
-pwl        Add lowercase chars to password generation
-pwu        Add uppercase chars to password generation
-pws        Add special chars to password generation
-pwspace    Add spaces to password generation
-pwss       Add safe special chars to password generation (Should not be used with -pws)

Example:
PassGen.exe -l 5 -n 1 -pwll -pwu -pws
Output: hT$la
PassGen.exe -p -l 3 -n 3 -wl -s &
Output: never&gonna&give you&up&never gonna&let&you
`

func PassphraseGen(p *atoll.Passphrase) [][]byte {
	passphrase, err := atoll.NewSecret(p)
	if err != nil {
		log.Fatal(err)
	}

	return passphrase
}

func PasswordGen(p *atoll.Password) [][]byte {
	password, err := atoll.NewSecret(p)
	if err != nil {
		log.Fatal(err)
	}

	return password
}

func WordListGen(path string) [][]byte {
	wordlist := [][]byte{}

	// open file
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	// remember to close the file at the end of the program
	defer f.Close()

	// read the file word by word using scanner
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanWords)

	// some diceware wordlists have info before the list, but every list starts with some form of 11 before the words
	wl_indexed := false
	r, _ := regexp.Compile("1[-|1]")

	for scanner.Scan() {
		// if we are at the word part of the list start adding them to the array
		if wl_indexed {
			if CheckWord(scanner.Text()) {
				wordlist = append(wordlist, []byte(scanner.Text()))
			}
		} else {
			// check if we made it to the 11 part yet
			if r.MatchString(scanner.Text()) {
				wl_indexed = true
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return wordlist
}

func CheckWord(word string) bool {
	valid_word := true
	for i := 0; i < len(word); i++ {
		if !unicode.IsLetter(int32(word[i])) && word[i] != '-' {
			valid_word = false
			fmt.Println("INVALID WORD: ", word)
			break
		}
	}
	return valid_word
}

func CsvOutput(name string, pass_list [][]byte) {
	// Write the CSV data
	file2, err := os.Create(name)
	if err != nil {
		panic(err)
	}
	defer file2.Close()

	writer := csv.NewWriter(file2)
	defer writer.Flush()
	// this defines the header value and data values for the new csv file
	headers := []string{"id", "password"}

	writer.Write(headers)
	for i := 0; i < len(pass_list); i++ {
		writer.Write([]string{strconv.Itoa(i), string(pass_list[i])})
	}
}

func main() {
	/*
		--------------------------------------------------------------------------------------------------------------
															ARGS
		--------------------------------------------------------------------------------------------------------------
	*/
	argsWithoutProg := os.Args[1:]
	//Is passphrase?
	passphrase_toggle := false
	//Letter/word count
	count := uint64(8)
	//output file name
	batch_count := uint64(1)
	//separator character
	separator := " "
	//wordlist txt file that holds all words used to generate passphrases
	wordlist_path := ""
	//atoll word list to use
	wordlist_type := atoll.NoList
	wlt := "nl"
	//password levels
	pw_levels := []atoll.Level{}
	//csv file
	csv_name := ""
	//Seed for random number generation (after sha256 hashing)
	seed := [32]byte{}

	for i := 0; i < len(argsWithoutProg); i++ {
		switch argsWithoutProg[i] {
		case "-h":
			fmt.Println(HELP)
			os.Exit(0)
		case "-p":
			passphrase_toggle = true
		case "-l":
			i++
			count, _ = strconv.ParseUint(argsWithoutProg[i], 10, 64)
		case "-n":
			i++
			batch_count, _ = strconv.ParseUint(argsWithoutProg[i], 10, 64)
		case "-s":
			i++
			separator = argsWithoutProg[i]
		case "-w":
			i++
			wordlist_path = argsWithoutProg[i]
		case "-csv":
			i++
			csv_name = argsWithoutProg[i]
		case "-wl":
			wordlist_type = atoll.WordList
			wlt = "wl"
		case "-wln":
			wordlist_type = atoll.WordListNum
			wlt = "wln"
		case "-wlc":
			wordlist_type = atoll.WordListCap
			wlt = "wlc"
		case "-wlnc":
			wordlist_type = atoll.WordListNumCap
			wlt = "wlnc"
		case "-wlcn":
			wordlist_type = atoll.WordListNumCap
			wlt = "wlcn"
		case "-pwl":
			pw_levels = append(pw_levels, atoll.Lower)
		case "-pwu":
			pw_levels = append(pw_levels, atoll.Upper)
		case "-pwd":
			pw_levels = append(pw_levels, atoll.Digit)
		case "-pwspace":
			pw_levels = append(pw_levels, atoll.Space)
		case "-pws":
			pw_levels = append(pw_levels, atoll.Special)
		case "-pwss":
			pw_levels = append(pw_levels, atoll.SafeSpecials)
		}
	}
	/*
		--------------------------------------------------------------------------------------------------------------
												Print ARGS + Get SEED
		--------------------------------------------------------------------------------------------------------------
	*/
	fmt.Printf("Use Passphrase: %v\n", passphrase_toggle)
	fmt.Printf("Password/Passphrase Length: %v\n", count)
	fmt.Printf("Batch Count: %v\n", batch_count)
	fmt.Printf("Seperator: %v\n", separator)
	fmt.Printf("Wordlist file: %v\n", wordlist_path)
	fmt.Printf("CSV File Name: %v\n", csv_name)

	fmt.Println("Enter Seed or Enter to continue")
	temp, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		os.Exit(1)
	}
	if temp != nil {
		seed = sha256.Sum256(temp)
		temp = nil
	}

	/*
		--------------------------------------------------------------------------------------------------------------
												PASSWORD / PASSPHRASE
		--------------------------------------------------------------------------------------------------------------
	*/

	if passphrase_toggle {
		// Setup Passphrases
		p := &atoll.Passphrase{
			Length:    count,
			Separator: separator,
			Number:    batch_count,
			Seed:      seed,
		}

		// Get wordlist if arg is passed
		if wordlist_path != "" {
			p.WordList = WordListGen(wordlist_path)
			// Get the wordlist type if arg is passed
			if wlt != "nl" {
				p.List = wordlist_type
			} else {
				p.List = atoll.WordList
			}
		} else {
			p.List = wordlist_type
		}

		// Make an array of byte strings that is as large as the number of passphrases generated
		pass_list := make([][]byte, batch_count)
		//Generate passwords
		pass_list = PassphraseGen(p)

		// Output to csv if arg is passed in
		if csv_name != "" {
			CsvOutput(csv_name, pass_list)
		} else {
			fmt.Println("Password(s):")
			for i := 0; i < int(batch_count); i++ {
				fmt.Println(string(pass_list[i]))
			}
		}

	} else {
		// Setup atoll Password
		p := &atoll.Password{
			Length: count,
			Number: batch_count,
			Seed:   seed,
			Repeat: false,
		}

		if len(pw_levels) > 0 {
			p.Levels = pw_levels
		} else {
			p.Levels = []atoll.Level{atoll.Lower, atoll.Upper, atoll.Digit, atoll.Special}
		}

		//Make an array of byte strings that is as large as the number of passwords generated
		pass_list := make([][]byte, batch_count)
		//Generate passwords
		pass_list = PasswordGen(p)

		//Output to csv or to console if no csv argument given
		if csv_name != "" {
			CsvOutput(csv_name, pass_list)
		} else {
			fmt.Println("Password(s):")
			for i := 0; i < int(batch_count); i++ {
				fmt.Println(string(pass_list[i]))
			}
		}
	}
}
