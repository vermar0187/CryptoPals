package cryptopals

import (
	"cmp"
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	rand2 "math/rand"
)

func generateBytes(count int) ([]byte, error) {
	b := make([]byte, count)
	_, err := rand.Read(b)
	return b, err
}

func pkcs7Padding(plainText []byte, blockSize int) []byte {
	if len(plainText)%blockSize == 0 {
		return plainText
	}

	paddingSize := blockSize - len(plainText)%blockSize
	for i := 0; i < paddingSize; i++ {
		plainText = append(plainText, byte(paddingSize))
	}

	return plainText
}

func stripPkcs7Padding(plainText []byte) []byte {
	startIdx := len(plainText) - 1
	paddingByte := plainText[startIdx]

	toStrip := 0
	for i := startIdx; i > startIdx-int(paddingByte); i-- {
		if plainText[i] == paddingByte {
			toStrip++
		} else {
			toStrip = 0
			break
		}
	}
	return plainText[:len(plainText)-toStrip]
}

func fixedByteXOR(byteArrOne []byte, byteArrTwo []byte) ([]byte, error) {
	if len(byteArrOne) != len(byteArrTwo) {
		return nil, errors.New(fmt.Sprintf("mismatch length between inputs: %s, %s", byteArrOne, byteArrTwo))
	}

	result := make([]byte, len(byteArrOne))
	for i := 0; i < len(result); i++ {
		result[i] = byteArrOne[i] ^ byteArrTwo[i]
	}
	return result, nil
}

func aes128CbcEncrypt(plainText []byte, cipherKey []byte, initializationVector []byte) (string, error) {
	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return "", err
	}

	paddedPlainText := pkcs7Padding(plainText, block.BlockSize())
	prevBlock := initializationVector
	result := make([]byte, len(paddedPlainText))
	for i := 0; i < len(plainText); i += aes.BlockSize {
		toEncryptBlock, xorErr := fixedByteXOR(paddedPlainText[i:i+aes.BlockSize], prevBlock)
		if xorErr != nil {
			return "", xorErr
		}
		block.Encrypt(result[i:i+aes.BlockSize], toEncryptBlock)
		prevBlock = result[i : i+aes.BlockSize]
	}
	return string(result), nil
}

func aes128CbcDecrypt(cipherText []byte, cipherKey []byte, initializationVector []byte) (string, error) {
	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return "", err
	}

	prevBlock := initializationVector
	result := make([]byte, len(cipherText))
	for i := 0; i < len(cipherText); i += aes.BlockSize {
		block.Decrypt(result[i:i+aes.BlockSize], cipherText[i:i+aes.BlockSize])
		xorResult, xorErr := fixedByteXOR(result[i:i+aes.BlockSize], prevBlock)
		if xorErr != nil {
			return "", xorErr
		}
		for j := i; j < i+aes.BlockSize; j++ {
			result[j] = xorResult[j-i]
		}
		prevBlock = cipherText[i : i+aes.BlockSize]
	}
	return string(stripPkcs7Padding(result)), nil
}

func aesEncryptionGenerator(plainText []byte) (string, string, error) {
	aesKey, keyErr := generateBytes(16)
	iv, ivErr := generateBytes(16)
	prePad, preErr := generateBytes(int(rand2.Int63n(6) + 5))
	postPad, postErr := generateBytes(int(rand2.Int63n(6) + 5))

	generateErr := cmp.Or(keyErr, preErr, postErr, ivErr)
	if generateErr != nil {
		return "", "", generateErr
	}

	plainText = pkcs7Padding(append(append(prePad, plainText...), postPad...), aes.BlockSize)
	shouldCbc := rand2.Int63n(2) == 1
	if shouldCbc {
		cipherText, err := aes128CbcEncrypt(plainText, aesKey, iv)
		return "CBC", cipherText, err
	} else {
		cipherText, err := aes128Encrypt(plainText, aesKey)
		return "ECB", cipherText, err
	}
}

func aesEncryptionOracle(cipherText []byte) string {
	if countDuplicateBytes(cipherText) > 0 {
		return "ECB"
	} else {
		return "CBC"
	}
}

func ExerciseNine(text string, blockSize int) (string, error) {
	cipherText := pkcs7Padding([]byte(text), blockSize)
	return string(cipherText), nil
}

func ExerciseTenA(data []byte, cipherKey string, initializationVector []byte) (string, error) {
	data, _ = base64.StdEncoding.DecodeString(string(data))
	return aes128CbcDecrypt(data, []byte(cipherKey), initializationVector)
}

func ExerciseTenB(plainText, cipherKey string, initializationVector []byte) (string, error) {
	data, err := aes128CbcEncrypt([]byte(plainText), []byte(cipherKey), initializationVector)
	if err != nil {
		return "", err
	}
	return aes128CbcDecrypt([]byte(data), []byte(cipherKey), initializationVector)
}

func ExerciseEleven() (string, error) {
	oracleAttempts := 1000
	oracleScore := 0
	for i := 0; i < oracleAttempts; i++ {
		randomRepeatedText := make([]byte, 64)
		repeatedByte := byte(rand2.Intn(255))
		for i := 0; i < len(randomRepeatedText); i++ {
			randomRepeatedText[i] = repeatedByte
		}
		generator, cipherText, err := aesEncryptionGenerator(randomRepeatedText)
		if err != nil {
			return "", err
		}
		if generator == aesEncryptionOracle([]byte(cipherText)) {
			oracleScore++
		}
	}

	return fmt.Sprintf("%d/%d", oracleScore, oracleAttempts), nil
}
