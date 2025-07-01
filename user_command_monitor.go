package main

import (
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	userCommandGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_logged_in_user_command",
			Help: "Tracks currently logged-in users and their last issued command.",
		},
		[]string{"user", "tty", "command"},
	)
	userCommandMutex sync.Mutex
)

func init() {
	prometheus.MustRegister(userCommandGauge)
}

func monitorUserCommands() {
	for {
		userCommandMutex.Lock()
		userCommandGauge.Reset()
		entries, err := getLoggedInUserCommands()
		if err == nil {
			for _, entry := range entries {
				userCommandGauge.WithLabelValues(entry.User, entry.TTY, entry.Command).Set(1)
			}
		}
		userCommandMutex.Unlock()
		time.Sleep(5 * time.Second)
	}
}

type UserCommandEntry struct {
	User    string
	TTY     string
	Command string
}

func getLoggedInUserCommands() ([]UserCommandEntry, error) {
	// Use 'who' and 'ps' to correlate users and their commands
	whoOut, err := exec.Command("who").Output()
	if err != nil {
		return nil, err
	}
	var entries []UserCommandEntry
	lines := strings.Split(string(whoOut), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		user := fields[0]
		tty := fields[1]
		// Find the last command for this TTY
		psOut, err := exec.Command("ps", "-t", tty, "-o", "args=", "--sort=start_time").Output()
		cmd := "unknown"
		if err == nil {
			psLines := strings.Split(strings.TrimSpace(string(psOut)), "\n")
			if len(psLines) > 0 {
				cmd = psLines[len(psLines)-1]
			}
		}
		entries = append(entries, UserCommandEntry{User: user, TTY: tty, Command: cmd})
	}
	return entries, nil
}
