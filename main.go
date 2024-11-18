package main

import (
	"fmt"
	"github.com/vermar0187/cryptopals/cryptopals"
	"os"
)

func writeExerciseResult(file *os.File, exerciseNum int, result string, err error) {
	var fileErr error
	if err == nil {
		_, fileErr = file.WriteString(fmt.Sprintf("Exercise %d: %s\n", exerciseNum, result))
	} else {
		_, fileErr = file.WriteString(fmt.Sprintf("Exercise %d errored: %s\n", exerciseNum, err.Error()))
	}

	if fileErr != nil {
		fmt.Printf("Error writing to file: %s\n", fileErr.Error())
	}
}

func setOne() {
	file, err := os.Create("results/set1_results.txt")
	if err != nil {
		fmt.Println("error creating file: ", err)
	}
	defer file.Close()

	// https://cryptopals.com/sets/1/challenges/1
	resultOne, err := cryptopals.ExerciseOne("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	writeExerciseResult(file, 1, resultOne, err)

	// https://cryptopals.com/sets/1/challenges/2
	resultTwo, err := cryptopals.ExerciseTwo("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965")
	writeExerciseResult(file, 2, resultTwo, err)

	// https://cryptopals.com/sets/1/challenges/3
	resultThree, err := cryptopals.ExerciseThree("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	writeExerciseResult(file, 3, resultThree, err)

	// https://cryptopals.com/sets/1/challenges/4
	dataFileFour, err := os.ReadFile("resources/set1_4.txt")
	var resultFour string
	if err != nil {
		writeExerciseResult(file, 4, resultFour, err)
	} else {
		resultFour, err = cryptopals.ExerciseFour(string(dataFileFour))
		writeExerciseResult(file, 4, resultFour, err)
	}

	// https://cryptopals.com/sets/1/challenges/5
	resultFive, err := cryptopals.ExerciseFive("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE")
	writeExerciseResult(file, 5, resultFive, err)

	// https://cryptopals.com/sets/1/challenges/6
	dataFileSix, err := os.ReadFile("resources/set1_6.txt")
	var resultSix string
	if err != nil {
		writeExerciseResult(file, 6, resultSix, err)
	} else {
		resultSix, err = cryptopals.ExerciseSix(string(dataFileSix))
		writeExerciseResult(file, 6, resultSix, err)
	}

	// https://cryptopals.com/sets/1/challenges/7
	dataFileSeven, err := os.ReadFile("resources/set1_7.txt")
	var resultSeven string
	if err != nil {
		writeExerciseResult(file, 7, resultSeven, err)
	} else {
		resultSeven, err = cryptopals.ExerciseSeven(string(dataFileSeven), "YELLOW SUBMARINE")
		writeExerciseResult(file, 7, resultSeven, err)
	}

	// https://cryptopals.com/sets/1/challenges/8
	dataFileEight, err := os.ReadFile("resources/set1_8.txt")
	var resultEight string
	if err != nil {
		writeExerciseResult(file, 8, resultEight, err)
	} else {
		resultEight, err = cryptopals.ExerciseEight(string(dataFileEight))
		writeExerciseResult(file, 8, resultEight, err)
	}
}

func setTwo() {
	file, err := os.Create("results/set2_results.txt")
	if err != nil {
		fmt.Println("error creating file: ", err)
	}
	defer file.Close()

	// https://cryptopals.com/sets/2/challenges/9
	resultNine, err := cryptopals.ExerciseNine("YELLOW SUBMARINE", 20)
	writeExerciseResult(file, 9, resultNine, err)

	// https://cryptopals.com/sets/2/challenges/10
	dataFileTen, err := os.ReadFile("resources/set2_10.txt")
	var resultTen string
	if err != nil {
		writeExerciseResult(file, 10, resultTen, err)
	} else {
		resultTenA, errA := cryptopals.ExerciseTenA(dataFileTen, "YELLOW SUBMARINE", make([]byte, 16))
		resultTenB, errB := cryptopals.ExerciseTenB("Nah... That dude on fire.", "YELLOW SUBMARINE",
			make([]byte, 16))
		if errA != nil {
			writeExerciseResult(file, 10, resultTenA, errA)
		} else if errB != nil {
			writeExerciseResult(file, 10, resultTenB, errB)
		} else {
			resultTen = resultTenA + "\n---------\n" + resultTenB
			writeExerciseResult(file, 10, resultTen, errB)
		}
	}

	// https://cryptopals.com/sets/2/challenges/11
	resultEleven, err := cryptopals.ExerciseEleven()
	writeExerciseResult(file, 11, resultEleven, err)
}

func main() {

	setOne()
	setTwo()
}
