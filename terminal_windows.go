//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func restoreTerminal() {
}

func listenForStop() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text == "s" || text == "S" {
			scanStopped.Store(true)
			fmt.Printf("\n%s Stopping scan... Results will be saved.\n", prompt)
			return
		}
	}
}
