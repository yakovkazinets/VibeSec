package main

import "os/exec"

func main() { exec.Command("/bin/sh", "-c", userInput).Run() }
