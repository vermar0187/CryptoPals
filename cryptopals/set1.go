package cryptopals

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode"
)

// Cryptopal set 1 challenges here: https://cryptopals.com/sets/1

var EnglishCharacterOccurrence = map[rune]float64{
	'a': 8.2389258, 'b': 1.5051398, 'c': 2.8065007, 'd': 4.2904556,
	'e': 12.813865, 'f': 2.2476217, 'g': 2.0327458, 'h': 6.1476691,
	'i': 6.1476691, 'j': 0.1543474, 'k': 0.7787989, 'l': 4.0604477,
	'm': 2.4271893, 'n': 6.8084376, 'o': 7.5731132, 'p': 1.9459884,
	'q': 0.0958366, 'r': 6.0397268, 's': 6.3827211, 't': 9.1357551,
	'u': 2.7822893, 'v': 0.9866131, 'w': 2.3807842, 'x': 0.1513210,
	'y': 1.9913847, 'z': 0.0746517, ' ': 20.0,
}

func chunkArray[T any](arr []T, chunkSize int) [][]T {
	var chunks [][]T
	for i := 0; i < len(arr); i += chunkSize {
		end := i + chunkSize
		if end > len(arr) {
			end = len(arr)
		}
		chunk := arr[i:end]
		chunks = append(chunks, chunk)
	}
	return chunks
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
	for char, percentage := range EnglishCharacterOccurrence {
		freq, ok := freqMap[char]
		var textPercentage float64
		if ok {
			textPercentage = float64(freq) / float64(len(resultString))
		} else {
			textPercentage = 0
		}
		sumOfAverage += math.Abs(textPercentage - percentage)
	}

	return sumOfAverage / float64(len(EnglishCharacterOccurrence))
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

func encryptRepeatedKey(text string, encryptionKey string) ([]byte, error) {
	byteKey := []byte(encryptionKey)
	byteText := []byte(text)

	result := make([]byte, len(byteText))
	for i := 0; i < len(result); i++ {
		result[i] = byteText[i] ^ byteKey[i%len(byteKey)]
	}

	return result, nil
}

func hammingDistance(byteArr1 []byte, byteArr2 []byte) int {
	var distance int

	maxLen := math.Max(float64(len(byteArr1)), float64(len(byteArr2)))
	for i := 0; i < int(maxLen); i++ {
		var toCheck byte
		if i >= len(byteArr1) {
			toCheck = byteArr2[i]
		} else if i >= len(byteArr2) {
			toCheck = byteArr1[i]
		} else {
			toCheck = byteArr1[i] ^ byteArr2[i]
		}

		for toCheck != 0 {
			distance++
			toCheck &= toCheck - 1
		}
	}

	return distance
}

func getKeySize(decodedBytes []byte, low int, high int) int {
	var minScore int
	var keySize int

	for i := low; i <= high; i++ {
		var score int

		for j := 0; j < len(decodedBytes)/(2*i); j++ {
			firstKeySizeBytes := decodedBytes[j : j+i]
			secondKeySizeBytes := decodedBytes[j+i : j+i+i]
			score += hammingDistance(firstKeySizeBytes, secondKeySizeBytes)
		}

		// normalization
		score /= i
		score /= len(decodedBytes) / (2 * i)

		if minScore == 0 || score < minScore {
			minScore = score
			keySize = i
		}
	}

	return keySize
}

func aes128Decrypt(cipherText []byte, cipherKey string) (string, error) {
	block, err := aes.NewCipher([]byte(cipherKey))
	if err != nil {
		return "", err
	}

	result := make([]byte, len(cipherText))
	for i := 0; i < len(cipherText); i += aes.BlockSize {
		block.Decrypt(result[i:i+aes.BlockSize], cipherText[i:i+aes.BlockSize])
	}
	return string(result), nil
}

func aes128Encrypt(plainText []byte, cipherKey []byte) (string, error) {
	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return "", err
	}

	result := make([]byte, len(plainText))
	for i := 0; i < len(plainText); i += aes.BlockSize {
		block.Encrypt(result[i:i+aes.BlockSize], plainText[i:i+aes.BlockSize])
	}
	return string(result), nil
}

func countDuplicateBytes(byteArr []byte) int {
	var count int

	hexBlockSet := map[string]struct{}{}
	for i := 0; i < len(byteArr); i += aes.BlockSize {
		hexBlock := hex.EncodeToString(byteArr[i : i+aes.BlockSize])
		_, ok := hexBlockSet[hexBlock]
		if ok {
			count++
		} else {
			hexBlockSet[hexBlock] = struct{}{}
		}
	}

	return count
}

func ExerciseOne(hexStr string) (string, error) {
	return hexToBase64(hexStr)
}

func ExerciseTwo(hexOne string, hexTwo string) (string, error) {
	return fixedXOR(hexOne, hexTwo)
}

func ExerciseThree(hexStr string) (string, error) {
	decipheredText, _, _, err := decipherSingleByteXor(hexStr)
	return decipheredText, err
}

func ExerciseFour(hexStr string) (string, error) {
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

func ExerciseFive(text string, encryptionKey string) (string, error) {
	result, err := encryptRepeatedKey(text, encryptionKey)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(result), nil
}

func ExerciseSix(base64Str string) (string, error) {
	decodedBytes, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		return "", errors.New(fmt.Sprintf("invalid base64 string: %s", base64Str))
	}

	keySize := getKeySize(decodedBytes, 2, 40)
	blocks := chunkArray(decodedBytes, keySize)
	var cipherKey string
	for i := range keySize {
		var transposedBlocks []byte
		for _, block := range blocks {
			if i < len(block) {
				transposedBlocks = append(transposedBlocks, block[i])
			}
		}
		_, blockKey, _, decipherErr := decipherSingleByteXor(hex.EncodeToString(transposedBlocks))
		if decipherErr != nil {
			return "", decipherErr
		}
		cipherKey += string(blockKey)
	}

	result, err := encryptRepeatedKey(string(decodedBytes), cipherKey)
	if err != nil {
		return "", err
	}
	return string(result), nil
}

func ExerciseSeven(base64Str string, cipherKey string) (string, error) {
	decodedBytes, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		return "", errors.New(fmt.Sprintf("invalid base64 string: %s", base64Str))
	}
	return aes128Decrypt(decodedBytes, cipherKey)
}

func ExerciseEight(hexLines string) (string, error) {
	var minCount int
	var result string

	for _, hexStr := range strings.Split(hexLines, "\n") {
		decodedBytes, err := hex.DecodeString(hexStr)
		if err != nil {
			return "", errors.New(fmt.Sprintf("invalid hex string: %s", hexStr))
		}
		count := countDuplicateBytes(decodedBytes)
		if count != 0 && (minCount == 0 || count < minCount) {
			minCount = count
			result = hexStr
		}
	}

	return result, nil
}
