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

	ifaces, err := pfInterfaces()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	for _, i := range ifaces {
		fmt.Printf("%v\n", i)
	}

	uptime, err := uptime()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(uptime)

	http.HandleFunc("/pf-states", func(w http.ResponseWriter, r *http.Request) {
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

	http.HandleFunc("/pf-rule-states", func(w http.ResponseWriter, r *http.Request) {
		rules, err := pfRuleStates()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
		jRules, err := json.Marshal(rules)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(jRules)
	})

	http.HandleFunc("/pf-info", func(w http.ResponseWriter, r *http.Request) {
		info, err := pfInfo()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
		jInfo, err := json.Marshal(info)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(jInfo)
	})

	http.HandleFunc("/pf-interfaces", func(w http.ResponseWriter, r *http.Request) {
		ifaces, err := pfInterfaces()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
		jIfaces, err := json.Marshal(ifaces)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(jIfaces)
	})

	http.ListenAndServe(":8001", nil)
}
