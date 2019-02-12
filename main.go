package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kless/osutil/user/crypt/apr1_crypt"
	"github.com/kless/osutil/user/crypt/md5_crypt"
	"github.com/kless/osutil/user/crypt/sha256_crypt"
	"github.com/kless/osutil/user/crypt/sha512_crypt"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh/terminal"
)

var version = "1.0.0"

func main() {
	hash, original := parseArguments()

	//Prompt for input where necessary
	if len(hash) == 0 {
		fmt.Print("HASH: ")
		fmt.Scanln(&hash)
	}
	if len(original) == 0 {
		fmt.Print("ORIGINAL (hidden): ")
		original, _ = terminal.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println("\n")
	}

	var hashType string
	var err error
	switch {
	case strings.HasPrefix(string(hash), "$1"):
		hashType = "MD5"
		err = md5_crypt.New().Verify(string(hash), original)
	case strings.HasPrefix(string(hash), "$apr1"): //Apache MD5
		hashType = "Apache MD5"
		err = apr1_crypt.New().Verify(string(hash), original)
	case strings.HasPrefix(string(hash), "$2"): //Blowfish
		hashType = "Blowfish"
		err = bcrypt.CompareHashAndPassword(hash, original)
	case strings.HasPrefix(string(hash), "$5"): //SHA256
		hashType = "SHA256"
		err = sha256_crypt.New().Verify(string(hash), original)
	case strings.HasPrefix(string(hash), "$6"): //SHA512
		hashType = "SHA512"
		err = sha512_crypt.New().Verify(string(hash), original)
	default:
		fmt.Printf("Unknown hash type\n")
		os.Exit(2)
	}

	if err != nil {
		fmt.Printf("%s hash was not produced from ORIGINAL: %s\n", hashType, err)
		os.Exit(1)
	}

	fmt.Printf("ORIGINAL %s hashes to HASH\n", hashType)
	os.Exit(0)
}

func parseArguments() (hash, original []byte) {
	switch len(os.Args) {
	case 3:
		original = []byte(os.Args[2])
		fallthrough
	case 2:
		if os.Args[1] == "-h" || os.Args[1] == "--help" {
			usage()
			os.Exit(0)
		}

		if os.Args[1] == "-v" || os.Args[1] == "--version" {
			fmt.Printf("v%s\n", version)
			os.Exit(0)
		}
		hash = []byte(os.Args[1])
	case 1:
	default:
		fmt.Fprintf(os.Stderr, "TOO MANY ARGUMENTS!!")
		os.Exit(2)
	}

	return
}

func usage() {
	fmt.Fprintf(os.Stderr, `USAGE:   
  %s [HASH] [ORIGINAL]

  If HASH and/or ORIGINAL are not provided, they will be prompted for.

  Return code is 0 if ORIGINAL hashes to HASH through means of the crypt algorithm HASH is of.
                 1 if the HASH could not have been produced by ORIGINAL
                 >1 if this could not be determined due to bad args or an unknown hash type
`, filepath.Base(os.Args[0]))
}
