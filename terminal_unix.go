//go:build !windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

var originalTermState *term.State

func setupRawMode() {
	fd := int(os.Stdin.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return
	}
	originalTermState = state
}

func restoreTerminal() {
	fd := int(os.Stdin.Fd())
	if originalTermState != nil {
		term.Restore(fd, originalTermState)
		originalTermState = nil
	}
}

func listenForStop() {
	setupRawMode()

	buf := make([]byte, 3)
	for {
		if scanStopped.Load() {
			restoreTerminal()
			return
		}
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			continue
		}
		if n == 1 && buf[0] == 19 {
			scanStopped.Store(true)
			restoreTerminal()
			fmt.Printf("\n%s Stopping scan... Results will be saved.\n", prompt)
			return
		}
		if n == 3 && buf[0] == 27 && buf[1] == 91 && buf[2] == 83 {
			scanStopped.Store(true)
			restoreTerminal()
			fmt.Printf("\n%s Stopping scan... Results will be saved.\n", prompt)
			return
		}
	}
}
