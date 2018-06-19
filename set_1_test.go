package cryptopals

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

func TestProblem1(t *testing.T) {
	output, err := hexStringToB64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	if err != nil {
		t.Fatal(err)
	}
	if output != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
		t.Fatal("Invalid response", output)
	}
}

func TestProblem2(t *testing.T) {
	output := xorByteSlices(hexStringDecode("1c0111001f010100061a024b53535009181c"), hexStringDecode("686974207468652062756c6c277320657965"))
	if !bytes.Equal(output, hexStringDecode("746865206b696420646f6e277420706c6179")) {
		t.Errorf("xor not working! %x", output)
	}
}

func TestProblem3(t *testing.T) {
	output, _, _ := bruteXOR(hexStringDecode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
	fmt.Printf("%s\n", output)
}

func TestProblem4(t *testing.T) {
	file, err := os.Open("data/4.txt")
	if err != nil {
		panic("Failed to read file!")
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)

	score := float64(1000000)
	var output []byte

	for scanner.Scan() {
		out, _, tmpScore := bruteXOR(hexStringDecode(scanner.Text()))
		if tmpScore < score {
			score = tmpScore
			output = out
		}
	}
	fmt.Printf("%s\n", output)
}

func TestProblem5(t *testing.T) {
	in := []byte(`Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`)
	out := repeatingXOR(in, []byte("ICE"))
	if !bytes.Equal(out, hexStringDecode("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")) {
		t.Error("wrong xor encryption: ", out)
	}
}

func TestHamming(t *testing.T) {
	output := hammingDistanceBytes([]byte("this is a test"), []byte("wokka wokka!!!"))
	if output != 37 {
		t.Error("Hamming distance is not 37, it's:", output)
	}
}

func TestProblem6(t *testing.T) {
	file, err := ioutil.ReadFile("data/6.txt")
	if err != nil {
		panic("Failed to read file!")
	}
	data := string(file)
	text, _ := base64.StdEncoding.DecodeString(data)
	fmt.Printf("Key is: '%s'\n", breakRepeatingXOR(text))
}

func TestProblem7(t *testing.T) {
	file, err := ioutil.ReadFile("data/7.txt")
	if err != nil {
		panic("Failed to read file!")
	}
	data := string(file)
	text, _ := base64.StdEncoding.DecodeString(data)
	block, _ := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	fmt.Printf("Decrypted to: '%s'\n", decryptAES128ECB(text, block)[:10])
}

func TestProblem8(t *testing.T) {
	file, err := ioutil.ReadFile("data/8.txt")
	if err != nil {
		panic("Failed to read file!")
	}
	data := string(file)
	for index, line := range strings.Split(data, "\n") {
		if detectECB(hexStringDecode(line), 16) {
			fmt.Printf("Line number %d is encrypted with ECB mode\n", index)
		}
	}
}
