package cryptopals

import (
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"math"
	"math/bits"
)

func hexStringToB64(input string) (string, error) {
	out, err := hex.DecodeString(input)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(out), nil
}

func calculateFreqIndex(input []byte) []float64 {
	var counts = make([]int, 256)
	var freq = make([]float64, 256)
	charCount := float64(0)

	for _, val := range input {
		counts[val] += 1
		charCount++
	}
	for index, val := range counts {
		freq[index] = float64(val) / charCount
	}

	return freq
}

func scoreText(base, target []float64) float64 {
	score := float64(0)
	for index := range base {
		score += math.Abs(base[index] - target[index])
	}

	return score
}

func singleByteXOR(input []byte, key byte) []byte {
	output := make([]byte, len(input))
	for i, c := range input {
		output[i] = c ^ key
	}
	return output
}

func bruteXOR(cipher []byte) ([]byte, byte, float64) {
	data, err := ioutil.ReadFile("data/pride.txt")
	if err != nil {
		panic("Failed to read file!")
	}
	freqIndex := calculateFreqIndex(data)
	var output []byte
	var key byte
	score := float64(1000000)
	for i := 0; i < 256; i++ {
		tmpOutput := singleByteXOR(cipher, byte(i))
		tmpScore := scoreText(freqIndex, calculateFreqIndex(tmpOutput))
		if tmpScore < score {
			score = tmpScore
			output = tmpOutput
			key = byte(i)
		}
	}
	return output, key, score
}

func xorByteSlices(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("Byte Slices of unequal lengths")
	}
	output := make([]byte, len(a))
	for i := range a {
		output[i] = a[i] ^ b[i]
	}
	return output
}

func hexStringDecode(s string) []byte {
	bytes, err := hex.DecodeString(s)
	if err != nil {
		panic("Failed to decode hex")
	}
	return bytes
}

func repeatingXOR(plain, key []byte) []byte {
	output := make([]byte, len(plain))
	rkey := make([]byte, 0)

	for len(rkey) < len(plain) {
		rkey = append(rkey, key...)
	}
	for i := range plain {
		output[i] = plain[i] ^ rkey[i]
	}
	return output
}

func hammingDistanceBytes(a, b []byte) int {
	var distance int = 0
	for index := range a {
		distance += bits.OnesCount8(a[index] ^ b[index])
	}
	return distance
}

func findRepeatingXORKeySize(cipher []byte) int {
	score := float64(10000000)
	var size int
	var tmpScore float64
	for keySize := 2; keySize < 40; keySize++ {
		tmpScore = 0
		iterations := len(cipher) / keySize
		for i := 0; i < iterations; i++ {
			f, s := cipher[i*keySize:(keySize*i)+keySize], cipher[keySize+(keySize*i):(keySize*i)+(keySize*2)]
			tmpScore += float64(hammingDistanceBytes(f, s))
		}
		tmpScore = tmpScore / float64(iterations) / float64(keySize)
		if tmpScore < score {
			score = tmpScore
			size = keySize
		}
	}
	return size
}

func breakRepeatingXOR(cipher []byte) []byte {
	keySize := findRepeatingXORKeySize(cipher)
	key := make([]byte, keySize)
	block := make([]byte, (len(cipher)+keySize-1)/keySize)
	for c := 0; c < keySize; c++ {
		for index := range block {
			if index*keySize+c >= len(cipher) {
				continue
			}
			block[index] = cipher[index*keySize+c]
		}
		_, char, _ := bruteXOR(block)
		key[c] = char
	}
	return key
}

func decryptAES128ECB(cipher []byte, block cipher.Block) []byte {
	blockSize := block.BlockSize()
	if len(cipher)%blockSize != 0 {
		panic("Cipher size must be a multiple of key size")
	}
	output := make([]byte, len(cipher))
	for i := 0; i < len(cipher); i += blockSize {
		block.Decrypt(output[i:], cipher[i:])
	}
	return output
}

func detectECB(cipher []byte, size int) bool {
	if len(cipher)%size != 0 {
		panic("Cipher size must be a multiple of key size")
	}
	detected := make(map[string]bool)
	for i := 0; i < len(cipher); i += size {
		out := string(cipher[i : i+size])
		if detected[out] {
			return true
		}
		detected[out] = true
	}
	return false
}
