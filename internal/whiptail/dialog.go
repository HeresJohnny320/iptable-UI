// Package whiptail is a classic menu-driven interface built on the system's
// whiptail dialogs, for people who prefer raspi-config style menus.
package whiptail

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/charmbracelet/x/term"
)

// Item is one entry in a menu: the tag is returned when it is chosen.
type Item struct {
	Tag   string
	Label string
}

// Dialog shows one dialog at a time. ok is false when the user cancels or
// presses Esc.
type Dialog interface {
	Menu(title, text string, items []Item, defaultTag string) (tag string, ok bool, err error)
	Input(title, text, initial string) (value string, ok bool, err error)
	YesNo(title, text string) (bool, error)
	Message(title, text string) error
}

// Whiptail runs the whiptail binary for each dialog.
type Whiptail struct {
	Path      string
	Backtitle string
}

// Find locates whiptail on PATH.
func Find() (string, error) {
	path, err := exec.LookPath("whiptail")
	if err != nil {
		return "", errors.New("whiptail is not installed (Debian/Ubuntu: apt install whiptail; Fedora: dnf install newt)")
	}
	return path, nil
}

func (w Whiptail) Menu(title, text string, items []Item, defaultTag string) (string, bool, error) {
	width, height := size(text, len(items))
	listHeight := max(1, min(len(items), height-textLines(text, width)-7))
	args := []string{"--title", title, "--ok-button", "Select", "--cancel-button", "Back"}
	if defaultTag != "" {
		args = append(args, "--default-item", defaultTag)
	}
	args = append(args, "--menu", text, strconv.Itoa(height), strconv.Itoa(width), strconv.Itoa(listHeight))
	for _, item := range items {
		args = append(args, item.Tag, item.Label)
	}
	return w.run(args)
}

func (w Whiptail) Input(title, text, initial string) (string, bool, error) {
	width, height := size(text, 1)
	return w.run([]string{"--title", title, "--inputbox", text, strconv.Itoa(height), strconv.Itoa(width), initial})
}

func (w Whiptail) YesNo(title, text string) (bool, error) {
	width, height := size(text, 0)
	_, ok, err := w.run([]string{"--title", title, "--yesno", text, strconv.Itoa(height), strconv.Itoa(width)})
	return ok, err
}

func (w Whiptail) Message(title, text string) error {
	width, height := size(text, 0)
	_, _, err := w.run([]string{"--title", title, "--scrolltext", "--msgbox", text, strconv.Itoa(height), strconv.Itoa(width)})
	return err
}

// run draws the dialog on the terminal and reads the answer, which whiptail
// writes to stderr. Exit status 1 (Cancel/No) and 255 (Esc) mean "not ok".
func (w Whiptail) run(args []string) (string, bool, error) {
	if w.Backtitle != "" {
		args = append([]string{"--backtitle", w.Backtitle}, args...)
	}
	command := exec.Command(w.Path, args...)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	var answer bytes.Buffer
	command.Stderr = &answer
	err := command.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) && (exit.ExitCode() == 1 || exit.ExitCode() == 255) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("whiptail: %w: %s", err, strings.TrimSpace(answer.String()))
	}
	return strings.TrimSpace(answer.String()), true, nil
}

// size fits a dialog to the terminal: at most 78 columns wide and tall
// enough for its text and list.
func size(text string, listItems int) (width, height int) {
	columns, rows, err := term.GetSize(os.Stdout.Fd())
	if err != nil || columns < 1 || rows < 1 {
		columns, rows = 80, 24
	}
	width = max(30, min(78, columns-4))
	height = textLines(text, width) + listItems + 8
	return width, max(7, min(height, rows-2))
}

// textLines estimates how many lines whiptail wraps text into.
func textLines(text string, width int) int {
	inner := max(1, width-4)
	lines := 0
	for _, line := range strings.Split(text, "\n") {
		lines += max(1, (len(line)+inner-1)/inner)
	}
	return lines
}
