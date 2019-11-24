package main

import (
	"encoding/json"
	"net/http"
)

func pfStatesHandler(w http.ResponseWriter, r *http.Request) {
	states, err := pfStates()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	encoded, err := json.Marshal(states)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*") // DEV
	w.Header().Set("Content-Type", "application/json")
	w.Write(encoded)
}

func pfRuleStatesHandler(w http.ResponseWriter, r *http.Request) {
	rules, err := pfRuleStates()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	encoded, err := json.Marshal(rules)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*") // DEV
	w.Header().Set("Content-Type", "application/json")
	w.Write(encoded)
}

func pfInfoHandler(w http.ResponseWriter, r *http.Request) {
	info, err := pfInfo()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	encoded, err := json.Marshal(info)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(encoded)
}

func pfInterfacesHandler(w http.ResponseWriter, r *http.Request) {
	ifaces, err := pfInterfaces()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	encoded, err := json.Marshal(ifaces)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*") // DEV
	w.Header().Set("Content-Type", "application/json")
	w.Write(encoded)
}

func uptimeHandler(w http.ResponseWriter, r *http.Request) {
	ut, err := uptime()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	encoded, err := json.Marshal(ut)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*") // DEV
	w.Header().Set("Content-Type", "application/json")
	w.Write(encoded)
}

func unameHandler(w http.ResponseWriter, r *http.Request) {
	un, err := uname()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	encoded, err := json.Marshal(un)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(encoded)
}

func rcAllHandler(w http.ResponseWriter, r *http.Request) {
	all, err := rcAll()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	encoded, err := json.Marshal(all)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*") // DEV
	w.Header().Set("Content-Type", "application/json")
	w.Write(encoded)
}

func rcOnHandler(w http.ResponseWriter, r *http.Request) {
	on, err := rcOn()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	encoded, err := json.Marshal(on)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*") // DEV
	w.Header().Set("Content-Type", "application/json")
	w.Write(encoded)
}

func rcStartedHandler(w http.ResponseWriter, r *http.Request) {
	started, err := rcStarted()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	encoded, err := json.Marshal(started)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*") // DEV
	w.Header().Set("Content-Type", "application/json")
	w.Write(encoded)
}

func netstatInterfacesHandler(w http.ResponseWriter, r *http.Request) {
	ifaces, err := netstatInterfaces()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	encoded, err := json.Marshal(ifaces)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*") // DEV
	w.Header().Set("Content-Type", "application/json")
	w.Write(encoded)
}
