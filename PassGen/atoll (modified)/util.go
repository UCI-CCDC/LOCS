package atoll

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"math/big"
	rand2 "math/rand/v2"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
)

var commonPatterns = regexp.MustCompile(`(?i)abc|123|qwerty|asdf|zxcv|1qaz|
zaq1|qazwsx|pass|login|admin|master|!@#$|!234|!Q@W`)

var pool = &sync.Pool{
	New: func() interface{} {
		return &bytes.Buffer{}
	},
}
var valid_seed = false
var seeded_rand *rand2.ChaCha8

func setSeed(s [32]byte) {
	seeded_rand = rand2.NewChaCha8(s)
	valid_seed = true
}

func randSeed(){
	buf := make([]byte, 8)
	seed := make([]byte, 32)
	for i:=1; i<=4; i++	{
		randN, _ := rand.Int(rand.Reader, big.NewInt(int64(255)))
		binary.LittleEndian.PutUint64(buf, randN.Uint64())
		for j:=1; j<=8; j++ {
			seed[j*i-1] = buf[j-1]
		}
	}
	seeded_rand = rand2.NewChaCha8([32]byte(seed))
	valid_seed = true

	// Wipe sensitive data
	for i := range buf {
		buf[i] = 0
	}
	for i := range seed {
		seed[i] = 0
	}
	// Keep buf alive so preceding loop is not optimized out
	runtime.KeepAlive(buf)
	runtime.KeepAlive(seed)
}

// getBuf returns a buffer from the pool.
func getBuf() *bytes.Buffer {
	return pool.Get().(*bytes.Buffer)
}

// putBuf resets buf and puts it back to the pool.
func putBuf(buf *bytes.Buffer) {
	buf.Reset()
	pool.Put(buf)
}

// getFuncName returns the name of the function passed.
func getFuncName(f list) string {
	// Example: github.com/GGP1/atoll.NoList
	fn := runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()

	lastDot := strings.LastIndexByte(fn, '.')
	return fn[lastDot+1:]
}

// randInt returns a cryptographically secure random integer in [0, max), using chacha8
func randInt(max int) int64 {
	// The error is skipped as max is always > 0.
	if !valid_seed {
		randSeed()
	}

	//Creativly barrowed from crytpo/rand
	if max <= 0 {
		panic("randInt: argument to Int is <= 0")
	}
	n := new(big.Int)
	n.Sub(big.NewInt(int64(max)), n.SetUint64(1))
	// bitLen is the maximum bit length needed to encode a value < max.
	bitLen := n.BitLen()
	if bitLen == 0 {
		// the only valid result is 0
		return int64(0)
	}
	// k is the maximum byte length needed to encode a value < max.
	k := (bitLen + 7) / 8
	// b is the number of bits in the most significant byte of max-1.
	b := uint(bitLen % 8)
	if b == 0 {
		b = 8
	}

	bytes := make([]byte, k)
	buf := make([]byte, 8)

	for {
		binary.LittleEndian.PutUint64(buf, seeded_rand.Uint64())
		bytes = buf[:k]

		// Clear bits in the first byte to increase the probability
		// that the candidate is < max.
		bytes[0] &= uint8(int(1<<b) - 1)

		n.SetBytes(bytes)
		if n.Cmp(big.NewInt(int64(max))) < 0 {
			return n.Int64()
		}
	}
}

// shuffle changes randomly the order of the password elements.
func shuffle(key []byte) []byte {
	for i := range key {
		j := randInt(i + 1)
		key[i], key[j] = key[j], key[i]
	}

	return key
}