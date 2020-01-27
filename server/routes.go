package main

import (
	"github.com/gorilla/mux"
	"net/http"
)

func main() {
	smalltest()
	r := mux.NewRouter()
	r.HandleFunc("/api/pf-states", pfStatesHandler).Methods("GET")
	r.HandleFunc("/api/pf-rule-states", pfRuleStatesHandler)
	r.HandleFunc("/api/pf-kill-id", pfKillIDHandler).Methods("POST")
	r.HandleFunc("/api/pf-info", pfInfoHandler).Methods("GET")
	r.HandleFunc("/api/pf-interfaces", pfInterfacesHandler)
	r.HandleFunc("/api/pf-memory", pfMemoryHandler)
	r.HandleFunc("/api/rc-all", GetRcAllHandler)
	r.HandleFunc("/api/rc-on", GetRcOnHandler)
	r.HandleFunc("/api/rc-started", GetRcStartedHandler)
	r.HandleFunc("/api/rc/{service}", GetRcServiceHandler)
	r.HandleFunc("/api/rc/{service}/flags", GetRcServiceFlagsHandler).Methods("GET")
	r.HandleFunc("/api/rc/{service}/flags", SetRcServiceFlagsHandler).Methods("POST")
	r.HandleFunc("/api/rc/{service}/started", GetRcServiceStartedHandler).Methods("GET")
	r.HandleFunc("/api/rc/{service}/started", SetRcServiceStartedHandler).Methods("POST")
	r.HandleFunc("/api/rc/{service}/enabled", GetRcServiceEnabledHandler).Methods("GET")
	r.HandleFunc("/api/rc/{service}/enabled", SetRcServiceEnabledHandler).Methods("POST")
	r.HandleFunc("/api/netstat-interfaces", netstatInterfacesHandler)
	r.HandleFunc("/api/uptime", uptimeHandler)
	r.HandleFunc("/api/uname", unameHandler)
	r.HandleFunc("/api/vmstat", vmstatHandler)
	r.HandleFunc("/api/disk-usage", diskUsageHandler)
	r.HandleFunc("/api/hardware", hardwareHandler)
	r.HandleFunc("/api/processes", processesHandler)
	r.HandleFunc("/api/swap-usage", swapUsageHandler)
	r.HandleFunc("/api/hostname", GetHostnameHandler)
	r.HandleFunc("/api/ram", GetRamHandler)
	r.HandleFunc("/api/cpu-states", GetCpuStatesHandler)

	http.ListenAndServe(":8001", r)
}
