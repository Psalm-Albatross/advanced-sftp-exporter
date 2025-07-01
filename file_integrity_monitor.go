package main

import (
	"crypto/sha256"
	"io/ioutil"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	fileIntegrityGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_file_integrity_change_detected",
			Help: "Detects changes to critical files/directories (1=changed, 0=unchanged)",
		},
		[]string{"path"},
	)
	fileIntegrityHashes = make(map[string][32]byte)
)

func init() {
	prometheus.MustRegister(fileIntegrityGauge)
}

func monitorFileIntegrity() {
	criticalPaths := []string{"/etc/ssh/sshd_config", "/etc/passwd"} // Add more as needed
	for {
		for _, path := range criticalPaths {
			data, err := ioutil.ReadFile(path)
			if err != nil {
				fileIntegrityGauge.WithLabelValues(path).Set(0)
				continue
			}
			hash := sha256.Sum256(data)
			if prev, ok := fileIntegrityHashes[path]; ok && prev != hash {
				fileIntegrityGauge.WithLabelValues(path).Set(1)
			} else {
				fileIntegrityGauge.WithLabelValues(path).Set(0)
			}
			fileIntegrityHashes[path] = hash
		}
		time.Sleep(30 * time.Second)
	}
}
