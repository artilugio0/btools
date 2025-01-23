package main

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"os"
	"strings"

	"github.com/artilugio0/btools"
)

func main() {
	// TODO: only allow raw entropy for base 2, 4 and 8
	rawEntropy := false
	dice := false
	usePassphrase := false
	base := 2   // [2, 10]
	words := 24 // 12 15 18 21 24

	wordsToInputBits := map[int]int{
		12: 128,
		15: 160,
		18: 192,
		21: 224,
		24: 256,
	}

	buf := bufio.NewReader(os.Stdin)
	bits, ok := wordsToInputBits[words]
	if !ok {
		panic("invalid words count")
	}
	bytes := bits / 8

	inputEntropyBuilder := strings.Builder{}
	neededSymbols := int(math.Ceil(float64(bits) / math.Log2(float64(base))))

	for inputEntropyBuilder.Len() < neededSymbols {
		s, err := buf.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			panic(err)
		}
		s = strings.TrimSpace(s)

		inputEntropyBuilder.WriteString(s)
	}
	inputEntropy := inputEntropyBuilder.String()

	if dice {
		var err error
		inputEntropy, err = btools.DiceToBase(inputEntropy, base)
		if err != nil {
			panic(err)
		}
	}

	var entropy []byte
	var err error
	if rawEntropy {
		if len(inputEntropy) != neededSymbols {
			panic("input does not have the required length")
		}
		entropy, err = btools.StringToEntropyRaw(inputEntropy, base, bits)
	} else {
		if len(inputEntropy) < neededSymbols {
			panic("input does not have enough length to produce the required entropy")
		}
		entropy, err = btools.StringToEntropyHash(inputEntropy)
	}
	if err != nil {
		panic(err)
	}

	passphrase := ""
	if usePassphrase {
		fmt.Print("Passphrase: ")
		passphrase, err = buf.ReadString('\n')
		if err != nil {
			panic(err)
		}
		passphrase = strings.TrimSpace(passphrase)
	}

	mnemonic, err := btools.Mnemonic(entropy[:bytes])
	if err != nil {
		panic(err)
	}

	seed, err := btools.NewSeed(mnemonic, passphrase)
	if err != nil {
		panic(err)
	}

	fmt.Println(seed.Mnemonic)
	for _, b := range entropy[:bytes] {
		fmt.Printf("%08b", b)
	}
	fmt.Println("")

	for _, b := range seed.Seed {
		fmt.Printf("%02x", b)
	}
	fmt.Println("")
}
