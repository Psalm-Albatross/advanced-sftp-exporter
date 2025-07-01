package main

import (
	"os/exec"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	sftpCommandCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_command_audit_total",
			Help: "Counts SFTP commands executed (put, get, rm, rename, etc.) per user.",
		},
		[]string{"user", "command"},
	)
)

func init() {
	prometheus.MustRegister(sftpCommandCounter)
}

func monitorSFTPCommandAudit() {
	for {
		// Example: parse audit logs or process list for SFTP commands
		// This is a placeholder: real implementation may require auditd or sftp-server logs
		// Here, we simulate by checking running sftp-server processes and their args
		out, err := exec.Command("ps", "-eo", "user,args").Output()
		if err == nil {
			lines := strings.Split(string(out), "\n")
			for _, line := range lines {
				fields := strings.Fields(line)
				if len(fields) < 2 {
					continue
				}
				user := fields[0]
				args := strings.Join(fields[1:], " ")
				for _, cmd := range []string{"put", "get", "rm", "rename", "mkdir", "rmdir"} {
					if strings.Contains(args, cmd) {
						sftpCommandCounter.WithLabelValues(user, cmd).Inc()
					}
				}
			}
		}
		time.Sleep(10 * time.Second)
	}
}
