package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"unicode"
)

// Cryptopal set challenges here: https://cryptopals.com/sets/1

var ENGLISH_CHARACTER_OCCURANCE = map[rune]float64{
	'a': 8.2389258, 'b': 1.5051398, 'c': 2.8065007, 'd': 4.2904556,
	'e': 12.813865, 'f': 2.2476217, 'g': 2.0327458, 'h': 6.1476691,
	'i': 6.1476691, 'j': 0.1543474, 'k': 0.7787989, 'l': 4.0604477,
	'm': 2.4271893, 'n': 6.8084376, 'o': 7.5731132, 'p': 1.9459884,
	'q': 0.0958366, 'r': 6.0397268, 's': 6.3827211, 't': 9.1357551,
	'u': 2.7822893, 'v': 0.9866131, 'w': 2.3807842, 'x': 0.1513210,
	'y': 1.9913847, 'z': 0.0746517, ' ': 20.0,
}

func hexToBase64(hexStr string) (string, error) {
	decodedBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", errors.New(fmt.Sprintf("invalid hex string: %s", hexStr))
	}

	return base64.StdEncoding.EncodeToString(decodedBytes), nil
}

func fixedXOR(hexStringOne string, hexStringTwo string) (string, error) {
	decodedBytesOne, errOne := hex.DecodeString(hexStringOne)
	if errOne != nil {
		return "", errors.New(fmt.Sprintf("invalid hex string: %s", hexStringOne))
	}

	decodedBytesTwo, errTwo := hex.DecodeString(hexStringTwo)
	if errTwo != nil {
		return "", errors.New(fmt.Sprintf("invalid hex string: %s", hexStringTwo))
	}

	if len(decodedBytesOne) != len(decodedBytesTwo) {
		return "", errors.New(fmt.Sprintf("mismatch length between inputs: %s, %s", hexStringOne, hexStringTwo))
	}

	result := make([]byte, len(decodedBytesOne))
	for i := 0; i < len(result); i++ {
		result[i] = decodedBytesOne[i] ^ decodedBytesTwo[i]
	}
	return hex.EncodeToString(result), nil
}

func xorAgainstByte(hexBytes []byte, toXor byte) []byte {
	result := make([]byte, len(hexBytes))
	for i := 0; i < len(result); i++ {
		result[i] = hexBytes[i] ^ toXor
	}
	return result
}

func fittingQuotient(hexBytes []byte) float64 {
	resultString := string(hexBytes)

	freqMap := make(map[rune]int)
	for _, char := range resultString {
		freqMap[unicode.ToLower(char)]++
	}

	var sumOfAverage float64
	for char, percentage := range ENGLISH_CHARACTER_OCCURANCE {
		freq, ok := freqMap[char]
		var textPercentage float64
		if ok {
			textPercentage = float64(freq) / float64(len(resultString))
		} else {
			textPercentage = 0
		}
		sumOfAverage += math.Abs(textPercentage - percentage)
	}

	return sumOfAverage / float64(len(ENGLISH_CHARACTER_OCCURANCE))
}

func decipherSingleByteXor(hexStr string) (string, rune, float64, error) {
	decodedBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", rune(0), 0, errors.New(fmt.Sprintf("invalid hex string: %s", hexStr))
	}

	var minFq float64
	var originalText []byte
	var encryptionKey rune
	for i := 0; i < 256; i++ {
		result := xorAgainstByte(decodedBytes, byte(i))
		fq := fittingQuotient(result)
		if minFq == 0 || minFq > fq {
			minFq = fq
			originalText = result
			encryptionKey = rune(i)
		}
	}
	return string(originalText), encryptionKey, minFq, nil
}

func exerciseOne(hexStr string) (string, error) {
	base64Str, err := hexToBase64(hexStr)
	return base64Str, err
}

func exerciseTwo(hexOne string, hexTwo string) (string, error) {
	xorResult, err := fixedXOR(hexOne, hexTwo)
	return xorResult, err
}

func exerciseThree(hexStr string) (string, error) {
	decipheredText, _, _, err := decipherSingleByteXor(hexStr)
	return decipheredText, err
}

func exerciseFour(hexStr string) (string, error) {
	var minFq float64
	var result string
	for _, line := range strings.Split(hexStr, "\n") {
		text, _, fq, _ := decipherSingleByteXor(line)
		if minFq == 0 || fq < minFq {
			minFq = fq
			result = text
		}
	}
	return result, nil
}

func printHelper(exerciseNum int, result string, err error) {
	if err == nil {
		fmt.Printf("Exercise %d: %s\n", exerciseNum, result)
	} else {
		fmt.Printf("Exercise %d errored: %s\n", exerciseNum, err.Error())
	}
}

func main() {
	// https://cryptopals.com/sets/1/challenges/1
	resultOne, err := exerciseOne("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	printHelper(1, resultOne, err)

	// https://cryptopals.com/sets/1/challenges/2
	resultTwo, err := exerciseTwo("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965")
	printHelper(2, resultTwo, err)

	// https://cryptopals.com/sets/1/challenges/3
	resultThree, err := exerciseThree("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	printHelper(3, resultThree, err)

	// https://cryptopals.com/sets/1/challenges/4
	data, err := os.ReadFile("resources/set1_4.txt")
	var resultFour string
	if err != nil {
		printHelper(4, resultFour, err)
	} else {
		resultFour, err = exerciseFour(string(data))
		printHelper(4, resultFour, err)
	}
}
