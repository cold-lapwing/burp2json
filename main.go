// main stays at the module root so `go install ...@latest` keeps producing the
// burp2json binary. The implementation lives in internal/burp2json.
package main

import (
	"os"

	b2j "github.com/cold-lapwing/burp2json/internal/burp2json"
)

func main() {
	os.Exit(b2j.Run(os.Args[1:]))
}
