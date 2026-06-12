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
			if ec.err != nil {
				fmt.Fprintln(os.Stderr, "notenv:", ec.err)
			}
			os.Exit(ec.code) // a child's code passes through silently (err nil)
		}
		fmt.Fprintln(os.Stderr, "notenv:", err)
		os.Exit(1)
	}
}
