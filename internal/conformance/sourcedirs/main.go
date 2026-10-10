// Command sourcedirs prints conformance.SourceDirs, one a line, for
// scripts/conformance/run.sh to tell vm.sh which source to copy in.
package main

import (
	"fmt"

	"github.com/dantecatalfamo/OPF/internal/conformance"
)

func main() {
	for _, d := range conformance.SourceDirs {
		fmt.Println(d)
	}
}
