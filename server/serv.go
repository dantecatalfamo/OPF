package main

import (
	"fmt"
	"net/http"
	"os"
	"github.com/gorilla/mux"
)

func main() {
	states, err := GetPfStates()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	for _, s := range states {
		fmt.Printf("%v\n", s)
	}

	rules, err := GetPfRuleStates()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	for _, r := range rules {
		fmt.Printf("%v\n", r)
	}

	info, err := GetPfInfo()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(info)

	ifaces, err := GetPfInterfaces()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	for _, i := range ifaces {
		fmt.Printf("%v\n", i)
	}

	ut, err := GetUptime()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(ut)

	un, err := GetUname()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(un)

	rcall, err := GetRcAll()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(rcall)

	srv, err := GetRcService("sshd")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("%v\n", srv)

	flags, err := GetRcServiceFlags("sshd")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("%v\n", flags)

	nsifaces, err := GetNetstatInterfaces()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	for _, iface := range nsifaces {
		fmt.Printf("%v\n", iface)
	}

	vmst, err := GetVmstat()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("%v\n", vmst)

	df, err := GetDiskUsage()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("%v\n", df)
	for _, fs := range df.Filesystems {
		fmt.Printf("%v\n", fs)
	}

	hw, err := GetHardware()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("%v\n", hw)
	for _, disk := range hw.Disks {
		fmt.Printf("%v\n", disk)
	}
	for _, sens := range hw.Sensors {
		fmt.Printf("%v\n", sens)
	}

	procs, err := GetProcesses()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	for _, proc := range procs {
		fmt.Printf("%v\n", proc)
	}

	swap, err := GetSwapUsage()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("%v\n", swap)
	for _, swapDev := range swap.Devices {
		fmt.Printf("%v\n", swapDev)
	}

	r := mux.NewRouter()

	r.HandleFunc("/api/pf-states", pfStatesHandler)
	r.HandleFunc("/api/pf-rule-states", pfRuleStatesHandler)
	r.HandleFunc("/api/pf-info", pfInfoHandler)
	r.HandleFunc("/api/pf-interfaces", pfInterfacesHandler)
	r.HandleFunc("/api/rc-all", rcAllHandler)
	r.HandleFunc("/api/rc-on", rcOnHandler)
	r.HandleFunc("/api/rc-started", rcStartedHandler)
	r.HandleFunc("/api/rc/{service}", rcServiceHandler)
	r.HandleFunc("/api/rc/{service}/flags", rcServiceFlagsHandler)
	r.HandleFunc("/api/netstat-interfaces", netstatInterfacesHandler)
	r.HandleFunc("/api/uptime", uptimeHandler)
	r.HandleFunc("/api/uname", unameHandler)
	r.HandleFunc("/api/vmstat", vmstatHandler)
	r.HandleFunc("/api/disk-usage", diskUsageHandler)
	r.HandleFunc("/api/hardware", hardwareHandler)
	r.HandleFunc("/api/processes", processesHandler)
	r.HandleFunc("/api/swap-usage", swapUsageHandler)

	http.ListenAndServe(":8001", r)
}
