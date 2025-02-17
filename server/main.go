package main

import (
	"fmt"

	kmip "github.com/infisical/infisical-kmip"
)

func main() {
	fmt.Println("Starting KMIP server...")
	kmip.StartServer()
}
