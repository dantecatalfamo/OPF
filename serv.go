package main

import (
	"os"
	"net/http"
	"fmt"
)


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

	http.HandleFunc("/api/pf-states", pfStatesHandler)
	http.HandleFunc("/api/pf-rule-states", pfRuleStatesHandler)
	http.HandleFunc("/api/pf-info", pfInfoHandler)
	http.HandleFunc("/api/pf-interfaces", pfInterfacesHandler)
	http.HandleFunc("/api/rc-all", rcAllHandler)
	http.HandleFunc("/api/rc-on", rcOnHandler)
	http.HandleFunc("/api/rc-started", rcStartedHandler)
	http.HandleFunc("/api/netstat-interfaces", netstatInterfacesHandler)
	http.HandleFunc("/api/uptime", uptimeHandler)
	http.HandleFunc("/api/uname", unameHandler)

	http.ListenAndServe(":8001", nil)
}
