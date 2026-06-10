package main

import (
	"errors"
	"fmt"
	"os"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		var ec *exitCodeError
		if errors.As(err, &ec) {
			os.Exit(ec.code) // child's exit code, not ours; no message
		}
		fmt.Fprintln(os.Stderr, "notenv:", err)
		os.Exit(1)
	}
}
