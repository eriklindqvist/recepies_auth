package log

import (
  "os"
  "fmt"
	"io"
)

func Err(message string) {
  print(os.Stderr, message)
}

func Panic(message string) {
  Err(message)
  os.Exit(1)
}

func Info(message string) {
  print(os.Stdout, message)
}

func print(w io.Writer, message string) {
  fmt.Fprintln(w, message)
}
