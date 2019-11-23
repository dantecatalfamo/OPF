package main

import (
	"os"
	"net/http"
	"fmt"
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

	ut, err := uptime()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(ut)

	un, err := uname()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(un)

	rcall, err := rcAll()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(rcall)

	nsifaces, err := netstatInterfaces()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	for _, iface := range nsifaces {
		fmt.Printf("%v\n", iface)
	}

	http.HandleFunc("/pf-states", pfStatesHandler)
	http.HandleFunc("/pf-rule-states", pfRuleStatesHandler)
	http.HandleFunc("/pf-info", pfInfoHandler)
	http.HandleFunc("/pf-interfaces", pfInterfacesHandler)
	http.HandleFunc("/rc-all", rcAllHandler)
	http.HandleFunc("/rc-on", rcOnHandler)
	http.HandleFunc("/rc-started", rcStartedHandler)
	http.HandleFunc("/uptime", uptimeHandler)
	http.HandleFunc("/uname", unameHandler)

	http.ListenAndServe(":8001", nil)
}
