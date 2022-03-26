package main

import "fmt"

func smalltest() {
	fmt.Println("Debug Tests")

	states, err := GetPfStates()
	if err != nil {
		panic(err)
	}
	for _, s := range states {
		fmt.Println("PF State:", s)
	}

	rules, err := GetPfRuleStates()
	if err != nil {
		panic(err)
	}
	for _, r := range rules {
		fmt.Println("PF Rule:", r)
	}

	info, err := GetPfInfo()
	if err != nil {
		panic(err)
	}
	fmt.Println("PF Info:", info)

	ifaces, err := GetPfInterfaces()
	if err != nil {
		panic(err)
	}
	for _, i := range ifaces {
		fmt.Println("PF Interface:", i)
	}

	mem, err := GetPfMemory()
	if err != nil {
		panic(err)
	}
	fmt.Println("PF Memory:", mem)

	un, err := GetUname()
	if err != nil {
		panic(err)
	}
	fmt.Println("Uname:", un)

	rcall, err := GetRcAll()
	if err != nil {
		panic(err)
	}
	fmt.Println("RC All:", rcall)

	srv, err := GetRcService("sshd")
	if err != nil {
		panic(err)
	}
	fmt.Println("SSHd Service:", srv)

	flags, err := GetRcServiceFlags("sshd")
	if err != nil {
		panic(err)
	}
	fmt.Println("SSHd Flags:", flags)

	started, err := GetRcServiceStarted("sshd")
	if err != nil {
		panic(err)
	}
	fmt.Println("SSHd Started:", started)

	enabled, err := GetRcServiceEnabled("sshd")
	if err != nil {
		panic(err)
	}
	fmt.Println("SSHd Enabled:", enabled)

	nsifaces, err := GetNetstatInterfaces()
	if err != nil {
		panic(err)
	}
	for _, iface := range nsifaces {
		fmt.Println("Netsat Interface:", iface)
	}

	vmst, err := GetVmstat()
	if err != nil {
		panic(err)
	}
	fmt.Println("VmStat:", vmst)

	df, err := GetDiskUsage()
	if err != nil {
		panic(err)
	}
	fmt.Println("Disk Usage:", df)
	for _, fs := range df.Filesystems {
		fmt.Println("Filesystem:", fs)
	}

	hw, err := GetHardware()
	if err != nil {
		panic(err)
	}
	fmt.Println("Hardware:", hw)
	for _, disk := range hw.Disks {
		fmt.Println("Disk:", disk)
	}
	for _, sens := range hw.Sensors {
		fmt.Println("Sensor:", sens)
	}

	procs, err := GetProcesses()
	if err != nil {
		panic(err)
	}
	for _, proc := range procs {
		fmt.Println("Process:", proc)
	}

	swap, err := GetSwapUsage()
	if err != nil {
		panic(err)
	}
	fmt.Println("Swap Usage:", swap)
	for _, swapDev := range swap.Devices {
		fmt.Println("Swap Device:", swapDev)
	}

	hostname, err := GetHostname()
	if err != nil {
		panic(err)
	}
	fmt.Println("Hostname:", hostname)

	ram, err := GetRAM()
	if err != nil {
		panic(err)
	}
	fmt.Println("RAM:", ram)

	cpuStates, err := GetCpuStates()
	if err != nil {
		panic(err)
	}
	fmt.Println("CPU States:", cpuStates)

	date, err := GetDate()
	if err != nil {
		panic(err)
	}
	fmt.Println("Date:", date)

	bootTime, err := GetBootTime()
	if err != nil {
		panic(err)
	}
	fmt.Println("Boot Time:", bootTime)

	loadavg, err := GetLoadAvg()
	if err != nil {
		panic(err)
	}
	fmt.Println("Load Average:", loadavg)

	wireguardInterfaces, err := GetWireguardInterfaces()
	if err != nil {
		panic(err)
	}
	fmt.Println("Wireguard Interfaces:")
	for _, iface := range wireguardInterfaces {
		fmt.Println(iface)
		for _, addr := range iface.Addresses {
			fmt.Println(iface.Name, "address", addr)
		}
		for _, peer := range iface.Peers {
			fmt.Println(iface.Name, "peer", peer)
		}
	}
}
