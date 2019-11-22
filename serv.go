package main

import (
	"os"
	// "io"
	// "io/ioutil"
	"net/http"
	"encoding/json"
	"fmt"
	// "strconv"
	// "strings"
)


// TODO: create PfRule struct
func main() {
	states, err := pfStates()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	for _, s := range states {
		fmt.Printf("%v\n", s)
	}

	rules, err := pfRuleStates()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	for _, r := range rules {
		fmt.Printf("%v\n", r)
	}

	info, err := pfInfo()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(info)

	http.HandleFunc("/states", func(w http.ResponseWriter, r *http.Request) {
		states, err := pfStates()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
		jStates, err := json.Marshal(states)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(jStates)
	})

	http.ListenAndServe(":8001", nil)
}
