package keepkey

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/fatih/color"
	"github.com/manifoldco/promptui"
)

// Prompt the user for a passphrase
func promptPassphrase() (string, error) {
	prompt := promptui.Prompt{
		Label: "Passphrase",
		Mask:  '*',
	}
	res, err := prompt.Run()
	if err != nil {
		return "", err
	}
	return res, nil
}

// Prompt the user for their pin
func promptPin() (string, error) {
	cyan := color.New(color.FgCyan).FprintFunc()
	magenta := color.New(color.FgMagenta).FprintFunc()
	magenta(os.Stdout, "Enter your pin using the corresponding positions shown on your device\n")
	cyan(os.Stdout, "7 | 8 | 9\n")
	cyan(os.Stdout, "4 | 5 | 6\n")
	cyan(os.Stdout, "1 | 2 | 3\n\n")

	// validation function for prompt testing if input is a valid number
	validate := func(in string) error {
		if _, err := strconv.Atoi(in); err != nil {
			return errors.New("Pin must be a number")
		}
		return nil
	}

	// Prompt the user for their pin
	prompt := promptui.Prompt{
		Label:    "Pin",
		Validate: validate,
		Mask:     '*',
	}
	res, err := prompt.Run()
	if err != nil {
		return "", err
	}
	return res, nil
}

// Prompt the user for the next character during the seed recovery process
func promptCharacter(word, char uint32) (string, error) {

	// Input validation function
	validate := func(input string) error {
		if input != "undo" && input != "next" && (len(input) > 1 || len(input) < 1) {
			return errors.New("Input must be a single letter (a-z) or \"undo\" or \"next\" ")
		}
		return nil
	}

	// Pretty colors for prompt
	green := color.New(color.FgGreen).Add(color.Underline).Add(color.Bold).SprintFunc()
	magenta := color.New(color.FgMagenta).Add(color.Underline).Add(color.Bold).SprintFunc()
	blue := color.New(color.FgCyan).SprintFunc()

	text := "Enter | " + green(fmt.Sprintf("word #%d", word+1)) + " | " + magenta(fmt.Sprintf("letter #%d", char+1)) + " |,"
	text += blue(" or type \"next\" to continue or \"undo\" to go back")
	prompt := promptui.Prompt{
		Label:    text,
		Validate: validate,
	}

	// Get input from user
	result, err := prompt.Run()
	if err != nil {
		return "", err
	}

	// Device uses <space> as signal to proceed to next word
	if result == "next" {
		result = " "
	}

	return result, nil
}

// Let the user know a button press is required to continue
func promptButton() {
	cyan := color.New(color.FgCyan).Add(color.Bold).SprintFunc()
	fmt.Println(cyan("Awaiting user button press"))
}
