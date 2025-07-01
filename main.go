// advanced-sftp-exporter/main.go

package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	largeTransferThreshold   = 500 * 1024 * 1024  // 500 MB
	anomalyTransferThreshold = 1024 * 1024 * 1024 // 1 GB
)

var enableStrictMode = flag.Bool("strict-mode", false, "Enable GDPR-safe mode (anonymize IPs, usernames)")

var (
	memoryThresholdBytes  = flag.Int64("memory-threshold", 500*1024*1024, "Memory usage threshold in bytes for alerting") // default: 500MB
	minValidUID           = flag.Int("min-uid", 1000, "Minimum UID to monitor (ignore system users)")
	includeShellUsersOnly = flag.Bool("include-shell-users-only", false, "Only consider users with valid shell (e.g. bash/sh)")
	sshdConfigPath        = flag.String("sshd-config-path", "/etc/ssh/sshd_config", "Path to sshd_config file")
)

var (
	// Configurable flags
	authLogPath          string
	homeBasePath         string
	uploadMarkerSuffix   string
	downloadMarkerSuffix string
	listenAddress        string
	idleThresholdSec     int
	ticksPerSecond       float64
	homeGlob             string
	homeRegex            string
	userRegex            *regexp.Regexp
	compiledHomeRegex    *regexp.Regexp

	// Logging
	logger *log.Logger

	// Prometheus metrics

	sftpUp = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "sftp_up",
			Help: "SFTP availability: 1 = OK (sshd + config + running), 0 = not ready",
		})

	userLoginType = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_linux_user_login_type",
			Help: "SFTP Login method per Linux user: 1 = SSH key, 0 = Password or Unknown",
		},
		[]string{"user"},
	)

	loginTypeCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_login_type_total",
			Help: "Login method type (key/password) observed per user",
		},
		[]string{"user", "method"},
	)

	userSessions = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_user_sessions_total",
			Help: "Current active SFTP sessions per user",
		},
		[]string{"user"},
	)

	sessionDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sftp_session_duration_seconds",
			Help:    "Duration of completed SFTP sessions per user",
			Buckets: prometheus.ExponentialBuckets(5, 1.5, 10),
		},
		[]string{"user"},
	)

	idleSessions = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_idle_sessions_total",
			Help: "Number of idle SFTP sessions per user (no activity for threshold)",
		},
		[]string{"user"},
	)

	uploadCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_upload_count",
			Help: "Number of uploaded files per user",
		},
		[]string{"user"},
	)

	uploadBytes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_upload_bytes_total",
			Help: "Total bytes uploaded per user",
		},
		[]string{"user"},
	)

	downloadBytes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_download_bytes_total",
			Help: "Total bytes downloaded per user",
		},
		[]string{"user"},
	)

	transferRate = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_transfer_rate_bytes_per_second",
			Help: "Approximate transfer rate (upload/download) per user",
		},
		[]string{"user"},
	)

	openFiles = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_open_files",
			Help: "Current open files per user",
		},
		[]string{"user"},
	)

	memUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_memory_usage_bytes",
			Help: "Memory usage (RSS) of SFTP sessions per user",
		},
		[]string{"user"},
	)

	memoryUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_user_memory_usage_bytes",
			Help: "Memory usage per user",
		},
		[]string{"user"},
	)

	cpuUsage = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_cpu_usage_seconds_total",
			Help: "Cumulative CPU time of SFTP sessions per user",
		},
		[]string{"user"},
	)

	cpu_Usage = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_user_cpu_usage_seconds_total",
			Help: "Cumulative CPU time of SFTP sessions per user",
		},
		[]string{"user"},
	)

	diskUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_disk_usage_bytes",
			Help: "Disk usage of user home directories",
		},
		[]string{"user"},
	)

	largeTransferDetected = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_large_transfer_detected_total",
			Help: "Large file transfers detected per user (>500MB)",
		},
		[]string{"user"},
	)

	failedLogins = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_failed_logins_total",
			Help: "Failed SFTP login attempts per user",
		},
		[]string{"user"},
	)

	fileErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_file_operation_errors_total",
			Help: "Errors during file operations per user",
		},
		[]string{"user"},
	)

	transferAnomalies = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_transfer_anomaly_detected_total",
			Help: "Detected anomalies in transfer patterns per user",
		},
		[]string{"user"},
	)

	loginEvents = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_login_events_total",
			Help: "Successful SFTP login events per user",
		},
		[]string{"user"},
	)

	lastUploadTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_last_upload_timestamp_seconds",
			Help: "Unix timestamp of last upload per user",
		},
		[]string{"user"},
	)

	lastDownloadTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_last_download_timestamp_seconds",
			Help: "Unix timestamp of last download per user",
		},
		[]string{"user"},
	)

	uploadFileTypeCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_upload_file_type_count",
			Help: "Count of uploaded files by type per user",
		},
		[]string{"user", "type"},
	)

	concurrentTransfers = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_concurrent_transfers_total",
			Help: "Current concurrent transfers per user",
		},
		[]string{"user"},
	)

	lastSourceIP = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_last_source_ip_info",
			Help: "Source IP of last login per user (label only)",
		},
		[]string{"user", "ip"},
	)

	// Security metrics for InfoSec Team to identify unusual logins attempt
	sudoFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_sudo_auth_failures_total",
			Help: "Total sudo authentication failures",
		},
		[]string{"user", "tty", "rhost"},
	)

	authFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_pam_auth_failures_total",
			Help: "PAM authentication failures",
		},
		[]string{"user", "service"},
	)

	rootLoginAttempts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_root_login_attempts_total",
			Help: "Login attempts to root user",
		},
		[]string{"source_ip"},
	)

	sshdRestarts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_sshd_restarts_total",
			Help: "SSHD restart count",
		},
		[]string{"host", "reason"},
	)

	accessViolations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_access_violations_total",
			Help: "SELinux/AppArmor access denials",
		},
		[]string{"policy", "exe"},
	)

	homeDirWarnings = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_home_directory_permission_warnings_total",
			Help: "Home directories that are world/group writable (potential misconfig).",
		},
		[]string{"user"},
	)

	unexpectedFileTypes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_unexpected_file_types_total",
			Help: "Suspicious or uncommon file extensions uploaded by user (e.g. .exe, .php, .sh)",
		},
		[]string{"user", "ext"},
	)

	failedLoginBurst = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_failed_login_window_total",
			Help: "Failed login attempts by user within time window",
		},
		[]string{"user"},
	)

	shellInvocations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_user_shell_invocations_total",
			Help: "Count of bash/sh spawned by SFTP users (should be 0)",
		},
		[]string{"user"},
	)

	sessionFrequency = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "sftp_user_session_frequency_total",
			Help: "Tracks session start frequency per user",
		},
		[]string{"user"},
	)

	sessionByHour = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sftp_user_session_hour_bucket",
			Help:    "Histogram of login frequency by hour of day (0–23)",
			Buckets: prometheus.LinearBuckets(0, 1, 24), // 0, 1, 2, ..., 23
		},
		[]string{"user"},
	)

	memoryThresholdExceeded = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_memory_threshold_exceeded",
			Help: "Memory usage over defined threshold (per user)",
		},
		[]string{"user"},
	)

	virtualMemoryUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sftp_linux_virtual_memory_usage_bytes",
			Help: "Virtual memory (VmSize) per user in bytes",
		},
		[]string{"user"},
	)

	// In-memory session state for session duration, idle detection etc.
	sessionState = make(map[string]map[string]time.Time) // map[user]map[sessionID]startTime
	sessionMutex sync.Mutex
)

func init() {
	// Register Prometheus metrics
	prometheus.MustRegister(sftpUp)
	prometheus.MustRegister(userLoginType)
	prometheus.MustRegister(loginTypeCounter)
	prometheus.MustRegister(userSessions)
	prometheus.MustRegister(sessionDuration)
	prometheus.MustRegister(idleSessions)
	prometheus.MustRegister(uploadCount)
	prometheus.MustRegister(uploadBytes)
	prometheus.MustRegister(downloadBytes)
	prometheus.MustRegister(transferRate)
	prometheus.MustRegister(openFiles)
	prometheus.MustRegister(memUsage)
	prometheus.MustRegister(memoryUsage)
	prometheus.MustRegister(cpuUsage)
	prometheus.MustRegister(cpu_Usage)
	prometheus.MustRegister(diskUsage)
	prometheus.MustRegister(largeTransferDetected)
	prometheus.MustRegister(failedLogins)
	prometheus.MustRegister(fileErrors)
	prometheus.MustRegister(transferAnomalies)
	prometheus.MustRegister(loginEvents)
	prometheus.MustRegister(lastUploadTimestamp)
	prometheus.MustRegister(lastDownloadTimestamp)
	prometheus.MustRegister(uploadFileTypeCount)
	prometheus.MustRegister(concurrentTransfers)
	prometheus.MustRegister(lastSourceIP)
	prometheus.MustRegister(unexpectedFileTypes)
	prometheus.MustRegister(sessionByHour)
	prometheus.MustRegister(
		sudoFailures,
		authFailures,
		rootLoginAttempts,
		sshdRestarts,
		accessViolations,
	)
	prometheus.MustRegister(memoryThresholdExceeded, virtualMemoryUsage)

	out, err := exec.Command("getconf", "CLK_TCK").Output()
	if err != nil {
		logger.Printf("Warning: fallback to default CLK_TCK=100: %v", err)
		ticksPerSecond = 100
	} else {
		tps, err := strconv.Atoi(strings.TrimSpace(string(out)))
		if err != nil {
			logger.Printf("Invalid CLK_TCK output: %v", err)
			ticksPerSecond = 100
		} else {
			ticksPerSecond = float64(tps)
		}
	}
}

func main() {
	// Parse flags
	flag.StringVar(&authLogPath, "auth-log", "/var/log/auth.log", "Path to auth.log")
	flag.StringVar(&homeBasePath, "home-base", "/home", "Base directory for user home dirs")
	flag.StringVar(&uploadMarkerSuffix, "upload-marker-suffix", ".uploaded", "Suffix for upload marker files")
	flag.StringVar(&downloadMarkerSuffix, "download-marker-suffix", ".downloaded", "Suffix for download marker files")
	flag.StringVar(&listenAddress, "web.listen-address", ":9115", "Address to listen on for web interface and telemetry.")
	flag.IntVar(&idleThresholdSec, "idle-threshold-seconds", 300, "Idle threshold for session idle detection in seconds")
	flag.StringVar(&homeGlob, "home-glob", "/home/*", "Glob pattern for user home dirs (e.g. /demo-ftp-*)")
	flag.StringVar(&homeRegex, "home-regex", "", "Regex pattern to further filter user home dirs (optional)")
	userRegexStr := flag.String("user-regex", "", "Regex to filter usernames")
	flag.Parse()

	if *enableStrictMode {
		logger.Println("🔐 STRICT MODE ENABLED: GDPR-safe mode activated.")
	}

	if *userRegexStr != "" {
		r, err := regexp.Compile(*userRegexStr)
		if err != nil {
			log.Fatalf("Invalid user regex: %v", err)
		}
		userRegex = r
	}

	// To support regex filtering

	if homeRegex != "" {
		var err error
		compiledHomeRegex, err = regexp.Compile(homeRegex)
		if err != nil {
			logger.Fatalf("Invalid --home-regex pattern: %v", err)
		}
	}

	// Init logger
	logger = log.New(os.Stdout, "sftp-exporter: ", log.LstdFlags|log.Lmicroseconds)

	logger.Println("Starting advanced-sftp-exporter...")
	logger.Printf("Auth log: %s, Home base: %s, Upload marker: %s, Download marker: %s",
		authLogPath, homeBasePath, uploadMarkerSuffix, downloadMarkerSuffix)

	// Collect metrics periodically
	go func() {
		for {
			collectLoginUsersMetrics()
			// Refresh every 30s
			// use time.Sleep(30 * time.Second) if you want loop-based scrape update
			return // Let Prometheus scrape on demand instead
		}
	}()

	// Start background routines (next parts...)
	go monitorAuthLog()
	go monitorFileTransfers()
	go monitorOpenFilesCPUAndMem()
	go monitorDiskUsage()
	go monitorIdleSessions()
	go monitorSFTPUp() // Check if Linux server running or used as SFTP server
	go pollOpenFiles()
	go pollMemoryUsage()
	go pollCPUUsage()

	// Start HTTP server for Prometheus metrics
	http.Handle("/metrics", promhttp.Handler())
	logger.Printf("Listening on %s", listenAddress)
	log.Fatal(http.ListenAndServe(listenAddress, nil))
}

// func monitorSFTPUp() {
// 	logger.Println("Starting SFTP up/down health monitor (with sshd + config check)...")

// 	ticker := time.NewTicker(30 * time.Second)

// 	for {
// 		<-ticker.C

// 		// 1. Check if sshd process is running
// 		sshdRunning := false
// 		if out, err := exec.Command("pgrep", "sshd").Output(); err == nil && len(out) > 0 {
// 			sshdRunning = true
// 		}

// 		// 2. Check if sshd_config contains "Subsystem sftp"
// 		configHasSFTP := false
// 		configData, err := os.ReadFile("/etc/ssh/sshd_config")
// 		if err == nil && strings.Contains(string(configData), "Subsystem sftp") {
// 			configHasSFTP = true
// 		}

// 		// 3. Check if sftp-server or internal-sftp process is active
// 		sftpRunning := false
// 		if out, err := exec.Command("pgrep", "-f", "sftp-server|internal-sftp").Output(); err == nil && len(out) > 0 {
// 			sftpRunning = true
// 		}

// 		// Final decision
// 		if sshdRunning && configHasSFTP && sftpRunning {
// 			sftpUp.Set(1)
// 			logger.Println("SFTP is UP ✅ (sshd + config + process OK)")
// 		} else {
// 			sftpUp.Set(0)
// 			logger.Printf("SFTP is DOWN ❌ — sshd=%v config=%v sftp-proc=%v",
// 				sshdRunning, configHasSFTP, sftpRunning)
// 		}
// 	}
// }

func monitorSFTPUp() {
	logger.Println("Starting SFTP health monitor (requires sshd + (sftp process or config))...")

	ticker := time.NewTicker(30 * time.Second)
	for {
		<-ticker.C

		sshdRunning := isSSHDRunning()
		sftpRunning := isSFTPProcessRunning()
		configHasSFTP := isSFTPConfigured(*sshdConfigPath)

		if sshdRunning && (sftpRunning || configHasSFTP) {
			sftpUp.Set(1)
			logger.Println("✅ SFTP is UP — sshd is running, and either sftp process or config is present.")
		} else {
			sftpUp.Set(0)
			logger.Printf("❌ SFTP is DOWN — sshdRunning=%v, sftpRunning=%v, configHasSFTP=%v",
				sshdRunning, sftpRunning, configHasSFTP)
		}
	}
}

func isSSHDRunning() bool {
	// Try systemctl
	if out, err := exec.Command("systemctl", "is-active", "sshd").Output(); err == nil {
		state := strings.TrimSpace(string(out))
		logger.Printf("systemctl sshd status: %s", state)
		if state == "active" {
			return true
		}
	} else {
		logger.Printf("systemctl check failed: %v", err)
	}

	// Fallback to pgrep
	out, err := exec.Command("pgrep", "sshd").Output()
	if err == nil && len(out) > 0 {
		logger.Printf("pgrep found sshd running")
		return true
	}
	logger.Printf("pgrep did not find sshd")
	return false
}

func isSFTPProcessRunning() bool {
	out, err := exec.Command("ps", "-eo", "comm").Output()
	if err != nil {
		logger.Printf("Failed to run ps: %v", err)
		return false
	}

	found := false
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "sftp-server" || line == "internal-sftp" {
			found = true
			break
		}
	}
	logger.Printf("sftp process running: %v", found)
	return found
}

func isSFTPConfigured(configPath string) bool {
	data, err := os.ReadFile(configPath)
	if err != nil {
		logger.Printf("Failed to read sshd config at %s: %v", configPath, err)
		return false
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Subsystem") && strings.Contains(line, "sftp") {
			logger.Printf("Found SFTP Subsystem line: %s", line)
			return true
		}
	}
	logger.Println("No SFTP Subsystem found in config")
	return false
}

// Get users from /etc/passwd with shell access
func getLoginUsers() ([]string, error) {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var users []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		username := parts[0]
		shell := parts[6]
		if strings.Contains(shell, "bash") || strings.Contains(shell, "sh") {
			users = append(users, username)
		}
	}
	return users, scanner.Err()
}

func checkKeyLogin(user string) float64 {
	usr, err := userLookup(user)
	if err != nil {
		return 0 // fallback to password
	}
	authKeysPath := filepath.Join(usr.HomeDir, ".ssh", "authorized_keys")
	info, err := os.Stat(authKeysPath)
	if err != nil || info.Size() == 0 {
		return 0 // password login (or unknown)
	}
	return 1 // SSH key login
}

// Get user info including home dir
func userLookup(username string) (*user.User, error) {
	return user.Lookup(username)
}

func collectLoginUsersMetrics() {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		log.Printf("Failed to open /etc/passwd: %v", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var scanned, skipped, exported int

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}

		username := parts[0]
		uidStr := parts[2]
		homeDir := parts[5]
		shell := parts[6]

		scanned++

		// Skip system users
		uid, err := strconv.Atoi(uidStr)
		if err != nil || uid < *minValidUID {
			skipped++
			continue
		}

		// Respect --include-shell-users-only
		if *includeShellUsersOnly && !strings.Contains(shell, "bash") && !strings.Contains(shell, "sh") {
			skipped++
			continue
		}

		// Regex filters
		if userRegex != nil && !userRegex.MatchString(username) {
			skipped++
			continue
		}
		if compiledHomeRegex != nil && !compiledHomeRegex.MatchString(homeDir) {
			skipped++
			continue
		}

		// Check home dir exists
		if _, err := os.Stat(homeDir); os.IsNotExist(err) {
			skipped++
			continue
		}

		// Check key login
		authKeys := filepath.Join(homeDir, ".ssh", "authorized_keys")
		info, err := os.Stat(authKeys)
		if err != nil || info.Size() == 0 {
			userLoginType.WithLabelValues(username).Set(0)
			loginTypeCounter.WithLabelValues(username, "password").Inc()
		} else {
			userLoginType.WithLabelValues(username).Set(1)
			loginTypeCounter.WithLabelValues(username, "key").Inc()
		}

		exported++
	}

	log.Printf("User login metrics summary: scanned=%d skipped=%d exported=%d", scanned, skipped, exported)
}

func monitorAuthLog() {
	logger.Println("Starting auth.log monitor...")

	file, err := os.Open(authLogPath)
	if err != nil {
		logger.Fatalf("Failed to open auth log: %v", err)
	}
	defer file.Close()

	file.Seek(0, io.SeekEnd)
	reader := bufio.NewReader(file)

	sessionOpenRe := regexp.MustCompile(`Accepted (\S+) for (\S+) from ([\d\.]+)`)
	failedLoginRe := regexp.MustCompile(`Failed (\S+) for (invalid user )?(\S+) from ([\d\.]+)`)
	sessionCloseRe := regexp.MustCompile(`session closed for user (\S+)`)

	var sessionCounter int64

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			logger.Printf("Error reading auth log: %v", err)
			continue
		}

		line = strings.TrimSpace(line)

		// --- SESSION OPEN ---

		if matches := sessionOpenRe.FindStringSubmatch(line); matches != nil {
			method := matches[1]
			username := matches[2]
			ip := matches[3]

			if !isUserMonitored(username) {
				continue
			}

			// GDPR: Anonymize IP if strict mode
			ipForLog := ip
			if *enableStrictMode {
				ipForLog = anonymizeIP(ip)
			}

			logger.Printf("Session opened: user=%s ip=%s method=%s", username, ipForLog, method)

			if strings.Contains(line, "session opened") &&
				strings.Contains(line, "for user") &&
				(strings.Contains(line, "bash") || strings.Contains(line, "sh")) {
				username := extractField(line, "user ")
				shellInvocations.WithLabelValues(username).Inc()
				logger.Printf("⚠️ Shell access detected: user=%s line=%s", username, line)
			}

			sessionMutex.Lock()
			if _, ok := sessionState[username]; !ok {
				sessionState[username] = make(map[string]time.Time)
			}
			sessionID := fmt.Sprintf("%d", sessionCounter)
			sessionCounter++
			sessionState[username][sessionID] = time.Now()
			sessionMutex.Unlock()

			userSessions.WithLabelValues(username).Inc()
			loginEvents.WithLabelValues(username).Inc()
			sessionFrequency.WithLabelValues(username).Inc()
			failedLoginBurst.WithLabelValues(username).Inc()

			now := time.Now()
			hour := float64(now.Hour())
			sessionByHour.WithLabelValues(username).Observe(hour)

			// Only export raw IP if not in strict mode
			if !*enableStrictMode {
				lastSourceIP.WithLabelValues(username, ip).Set(1)
			}
		}

		// --- FAILED LOGIN ---
		if matches := failedLoginRe.FindStringSubmatch(line); matches != nil {
			method := matches[1]
			invalidUserPrefix := matches[2]
			username := matches[3]
			ip := matches[4]

			if !isUserMonitored(username) {
				continue
			}

			ipForLog := ip
			if *enableStrictMode {
				ipForLog = anonymizeIP(ip)
			}

			if invalidUserPrefix != "" {
				logger.Printf("Failed login (invalid user): user=%s ip=%s method=%s", username, ipForLog, method)
			} else {
				logger.Printf("Failed login: user=%s ip=%s method=%s", username, ipForLog, method)
			}

			failedLogins.WithLabelValues(username).Inc()
		}

		// --- SESSION CLOSE ---
		if matches := sessionCloseRe.FindStringSubmatch(line); matches != nil {
			user := matches[1]

			if !isUserMonitored(user) {
				continue
			}

			logger.Printf("Session closed: user=%s", user)

			sessionMutex.Lock()
			userSessions.WithLabelValues(user).Dec()

			if len(sessionState[user]) > 0 {
				var oldestSession string
				var oldestTime time.Time
				first := true
				for sid, startTime := range sessionState[user] {
					if first || startTime.Before(oldestTime) {
						oldestSession = sid
						oldestTime = startTime
						first = false
					}
				}

				if oldestSession != "" {
					duration := time.Since(oldestTime).Seconds()
					sessionDuration.WithLabelValues(user).Observe(duration)
					delete(sessionState[user], oldestSession)

					logger.Printf("Session duration recorded: user=%s duration=%.2fs", user, duration)
				}
			}

			sessionMutex.Unlock()
		}
	}
}

func anonymizeIP(ip string) string {
	if strings.Count(ip, ".") == 3 {
		parts := strings.Split(ip, ".")
		if len(parts) == 4 {
			return fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
		}
	}
	return "masked"
}

func monitorFileTransfers() {
	logger.Println("Starting file transfer monitor...")

	for {
		err := filepath.Walk(homeBasePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				logger.Printf("Walk error: %v", err)
				return nil // skip error
			}

			if info.IsDir() {
				return nil
			}

			// Check for upload marker files
			if strings.HasSuffix(path, uploadMarkerSuffix) {
				user, err := extractUserFromPath(path)
				if err != nil || !isUserMonitored(user) {
					return nil
				}

				origFilePath := strings.TrimSuffix(path, uploadMarkerSuffix)
				fileSize := getFileSize(origFilePath)
				fileType := getFileType(origFilePath)

				uploadCount.WithLabelValues(user).Inc()
				uploadBytes.WithLabelValues(user).Add(float64(fileSize))
				uploadFileTypeCount.WithLabelValues(user, fileType).Inc()
				lastUploadTimestamp.WithLabelValues(user).Set(float64(time.Now().Unix()))

				logger.Printf("Upload detected: user=%s file=%s size=%d bytes type=%s", user, origFilePath, fileSize, fileType)

				// 🚨 Suspicious file type detection
				suspiciousExts := []string{".exe", ".php", ".sh", ".bin", ".bat"}
				for _, ext := range suspiciousExts {
					if strings.HasSuffix(origFilePath, ext) {
						unexpectedFileTypes.WithLabelValues(user, ext).Inc()
						logger.Printf("🚨 Suspicious file uploaded: user=%s ext=%s", user, ext)
					}
				}

				// Large transfer?
				if fileSize > largeTransferThreshold {
					largeTransferDetected.WithLabelValues(user).Inc()
					logger.Printf("Large transfer detected: user=%s size=%d bytes", user, fileSize)
				}

				// Anomaly detection
				if fileSize > anomalyTransferThreshold {
					transferAnomalies.WithLabelValues(user).Inc()
					logger.Printf("Anomaly detected: user=%s size=%d bytes", user, fileSize)
				}

				// Track concurrent transfers → dummy simple counter
				concurrentTransfers.WithLabelValues(user).Inc()
				time.AfterFunc(10*time.Second, func() {
					concurrentTransfers.WithLabelValues(user).Dec()
				})

				// Optional: delete marker (best to avoid duplicate counting)
				// os.Remove(path)
			}

			// Check for download marker files
			if strings.HasSuffix(path, downloadMarkerSuffix) {
				user, err := extractUserFromPath(path)
				if err != nil || !isUserMonitored(user) {
					return nil
				}

				origFilePath := strings.TrimSuffix(path, downloadMarkerSuffix)
				fileSize := getFileSize(origFilePath)
				fileType := getFileType(origFilePath)

				downloadBytes.WithLabelValues(user).Add(float64(fileSize))
				lastDownloadTimestamp.WithLabelValues(user).Set(float64(time.Now().Unix()))

				logger.Printf("Download detected: user=%s file=%s size=%d bytes type=%s", user, origFilePath, fileSize, fileType)

				// Optional: delete marker (recommended)
				// os.Remove(path)
			}

			return nil
		})

		if err != nil {
			logger.Printf("Error in Walk: %v", err)
		}

		time.Sleep(10 * time.Second) // Polling interval
	}
}

func extractUserFromPath(path string) (string, error) {
	relPath, err := filepath.Rel(homeBasePath, path)
	if err != nil {
		logger.Printf("Error getting relative path for %s: %v", path, err)
		return "", err
	}

	parts := strings.Split(relPath, string(os.PathSeparator))
	if len(parts) < 1 || parts[0] == "." || parts[0] == "" {
		logger.Printf("Cannot extract user from path: %s (relPath=%s)", path, relPath)
		return "", fmt.Errorf("cannot extract user from path: %s", path)
	}

	user := parts[0]

	// Optional: skip users not monitored (if homeRegex is used)
	if !isUserMonitored(user) {
		logger.Printf("Skipping unmonitored user extracted from path: %s → %s", path, user)
		return "", fmt.Errorf("user %s not monitored", user)
	}

	logger.Printf("Extracted user=%s from path=%s", user, path)

	return user, nil
}

func getFileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		var errorLabel string
		if os.IsNotExist(err) {
			errorLabel = "notfound"
		} else if os.IsPermission(err) {
			errorLabel = "permission"
		} else {
			errorLabel = "unknown"
		}

		fileErrors.WithLabelValues(errorLabel).Inc()
		logger.Printf("Error getting size for %s: %v", path, err)

		return 0
	}

	size := fi.Size()
	logger.Printf("File size for %s → %d bytes", path, size)

	return size
}

func getFileType(path string) string {
	out, err := exec.Command("file", "--mime-type", "-b", path).Output()
	if err != nil {
		logger.Printf("Error detecting MIME type for %s: %v", path, err)
		fileErrors.WithLabelValues("unknown").Inc()
		return "unknown"
	}

	mimeType := strings.TrimSpace(string(out))
	logger.Printf("Detected MIME type for %s → %s", path, mimeType)
	return mimeType
}

// Monitor both CPU and Open Files Per User
func monitorOpenFilesCPUAndMem() {
	logger.Println("Starting open files + CPU/mem monitor...")

	ticker := time.NewTicker(15 * time.Second)

	for {
		<-ticker.C

		userProcMap := make(map[string][]int) // user → list of SFTP PIDs

		// Find SFTP processes and group by user
		out, err := exec.Command("ps", "-eo", "pid,user,comm").Output()
		if err != nil {
			logger.Printf("Error running ps: %v", err)
			continue
		}

		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "sftp-server") || strings.Contains(line, "internal-sftp") {
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					pidStr := fields[0]
					user := fields[1]

					pid, err := strconv.Atoi(pidStr)
					if err != nil {
						continue
					}

					userProcMap[user] = append(userProcMap[user], pid)
				}
			}
		}

		for user, pids := range userProcMap {
			if !isUserMonitored(user) {
				logger.Printf("Skipping user=%s (not matching regex/glob)", user)
				continue
			}

			logger.Printf("Processing user=%s → %d SFTP processes", user, len(pids))

			totalOpenFiles := 0
			totalMem := int64(0)
			totalCPU := float64(0)

			for _, pid := range pids {
				// Filter open files
				lsofOut, err := exec.Command("lsof", "-p", fmt.Sprintf("%d", pid)).Output()
				if err == nil {
					count := 0
					scanner := bufio.NewScanner(bytes.NewReader(lsofOut))
					for scanner.Scan() {
						line := scanner.Text()
						if strings.Contains(line, homeBasePath) &&
							!strings.Contains(line, "/lib") &&
							!strings.Contains(line, ".so") &&
							!strings.Contains(line, ".bash") &&
							!strings.Contains(line, "/proc/") &&
							!strings.Contains(line, "/dev/") {
							count++
						}
					}
					totalOpenFiles += count
					logger.Printf("PID %d open SFTP files in %s → %d", pid, homeBasePath, count)
				} else {
					logger.Printf("Error running lsof for PID %d: %v", pid, err)
				}

				// Memory usage
				memBytes, err := getProcMem(pid)
				if err == nil {
					totalMem += memBytes
					logger.Printf("PID %d mem → %d bytes", pid, memBytes)
				} else {
					logger.Printf("Error getting mem for PID %d: %v", pid, err)
				}

				// CPU usage
				cpuSecs, err := getProcCPU(pid)
				if err == nil {
					totalCPU += cpuSecs
					logger.Printf("PID %d CPU → %.2f seconds", pid, cpuSecs)
				} else {
					logger.Printf("Error getting CPU for PID %d: %v", pid, err)
				}

				logger.Printf("PID %d memory = %dB, CPU = %.2fs", pid, memBytes, cpuSecs)
			}

			// Export metrics
			openFiles.WithLabelValues(user).Set(float64(totalOpenFiles))
			memUsage.WithLabelValues(user).Set(float64(totalMem))
			cpuUsage.WithLabelValues(user).Add(totalCPU)

			logger.Printf("Exported: user=%s open_files=%d mem=%dB cpu=%.2fs",
				user, totalOpenFiles, totalMem, totalCPU)
		}
	}
}

func getProcMem(pid int) (int64, error) {
	statmPath := fmt.Sprintf("/proc/%d/statm", pid)
	data, err := os.ReadFile(statmPath)
	if err != nil {
		logger.Printf("Error reading %s: %v", statmPath, err)
		return 0, err
	}

	parts := strings.Fields(string(data))
	if len(parts) < 2 {
		logger.Printf("Invalid format in %s", statmPath)
		return 0, fmt.Errorf("invalid statm format")
	}

	rssPages, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		logger.Printf("Error parsing RSS pages for PID %d: %v", pid, err)
		return 0, err
	}

	pageSize := int64(os.Getpagesize())
	rssBytes := rssPages * pageSize

	logger.Printf("Memory usage for PID %d → %d bytes", pid, rssBytes)

	return rssBytes, nil
}

// Get CPU Metircs
func getProcCPU(pid int) (float64, error) {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	data, err := os.ReadFile(statPath)
	if err != nil {
		logger.Printf("Error reading %s: %v", statPath, err)
		return 0, err
	}

	parts := strings.Fields(string(data))
	if len(parts) < 17 {
		logger.Printf("Invalid format in %s", statPath)
		return 0, fmt.Errorf("invalid stat format")
	}

	utimeTicks, err1 := strconv.ParseFloat(parts[13], 64)
	stimeTicks, err2 := strconv.ParseFloat(parts[14], 64)

	if err1 != nil || err2 != nil {
		logger.Printf("Error parsing CPU times for PID %d: utimeErr=%v stimeErr=%v", pid, err1, err2)
		return 0, fmt.Errorf("error parsing CPU times")
	}

	// ticksPerSecond := float64(100) // Typical Linux value, can be tuned

	totalSeconds := (utimeTicks + stimeTicks) / ticksPerSecond

	logger.Printf("CPU time for PID %d → %.2f seconds", pid, totalSeconds)

	return totalSeconds, nil
}

// Monitoring of Insecure Home directory access
func monitorInsecureHomeDirs() {
	logger.Println("Checking home dir permissions...")

	ticker := time.NewTicker(15 * time.Minute)
	for {
		<-ticker.C
		matches, _ := filepath.Glob("/home/*")
		for _, dir := range matches {
			info, err := os.Stat(dir)
			if err != nil || !info.IsDir() {
				continue
			}
			mode := info.Mode().Perm()
			if mode&0022 != 0 {
				user := filepath.Base(dir)
				homeDirWarnings.WithLabelValues(user).Inc()
				logger.Printf("⚠️ Insecure home dir %s: mode=%#o", dir, mode)
			}
		}
	}
}

// Metrics to collect security related issues for quick actions and unusual activity detections
func monitorSyslogSecurityEvents() {
	logger.Println("Starting syslog security event monitor...")

	syslogPath := "/var/log/syslog"
	if _, err := os.Stat("/var/log/messages"); err == nil {
		syslogPath = "/var/log/messages"
	}

	file, err := os.Open(syslogPath)
	if err != nil {
		logger.Printf("Error opening syslog: %v", err)
		return
	}
	defer file.Close()

	file.Seek(0, io.SeekEnd)
	reader := bufio.NewReader(file)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			logger.Printf("Error reading syslog: %v", err)
			continue
		}
		line = strings.TrimSpace(line)

		// --- sudo authentication failure
		if strings.Contains(line, "sudo") && strings.Contains(line, "authentication failure") {
			user := extractField(line, "user=")
			tty := extractField(line, "tty=")
			rhost := extractField(line, "rhost=")
			sudoFailures.WithLabelValues(user, tty, rhost).Inc()
			logger.Printf("Sudo failure: user=%s tty=%s rhost=%s", user, tty, rhost)
		}

		// --- PAM authentication failure
		if strings.Contains(line, "pam_unix") && strings.Contains(line, "authentication failure") {
			user := extractField(line, "user=")
			service := extractField(line, "pam_unix(")
			if idx := strings.Index(service, ":"); idx != -1 {
				service = service[:idx]
			}
			authFailures.WithLabelValues(user, service).Inc()
			logger.Printf("PAM failure: user=%s service=%s", user, service)
		}

		// --- root login attempt
		if strings.Contains(line, "sshd") && strings.Contains(line, "user root") {
			ip := extractField(line, "from ")
			rootLoginAttempts.WithLabelValues(ip).Inc()
			logger.Printf("Root login attempt from: %s", ip)
		}

		// --- sshd restart
		if strings.Contains(line, "sshd") &&
			(strings.Contains(line, "Starting OpenSSH") || strings.Contains(line, "sshd starting") || strings.Contains(line, "restarted")) {
			host := extractHostname(line)
			reason := "unknown"
			if strings.Contains(line, "manual") {
				reason = "manual-restart"
			}
			sshdRestarts.WithLabelValues(host, reason).Inc()
			logger.Printf("SSHD restart on host=%s reason=%s", host, reason)
		}

		// --- SELinux/AppArmor violations
		if strings.Contains(line, "audit") && strings.Contains(line, "AVC") {
			policy := extractField(line, "type=")
			exe := extractField(line, "exe=")
			accessViolations.WithLabelValues(policy, exe).Inc()
			logger.Printf("Access violation: policy=%s exe=%s", policy, exe)
		}
	}
}

func extractField(line, prefix string) string {
	idx := strings.Index(line, prefix)
	if idx == -1 {
		return "unknown"
	}
	after := line[idx+len(prefix):]
	fields := strings.Fields(after)
	if len(fields) > 0 {
		return strings.Trim(fields[0], ";,[]")
	}
	return "unknown"
}

// Check hostname
func extractHostname(line string) string {
	fields := strings.Fields(line)
	if len(fields) >= 4 {
		return fields[3]
	}
	return "unknown"
}

// Monitor Disk Usage
func monitorDiskUsage() {
	logger.Println("Starting disk usage monitor...")

	ticker := time.NewTicker(60 * time.Second)

	for {
		<-ticker.C

		var userDirs []string

		if homeGlob != "" {
			matches, err := filepath.Glob(homeGlob)
			if err != nil {
				logger.Printf("Error in home glob pattern: %v", err)
				continue
			}
			userDirs = matches
		} else {
			entries, err := os.ReadDir(homeBasePath)
			if err != nil {
				logger.Printf("Error reading home base dir: %v", err)
				continue
			}

			for _, entry := range entries {
				if entry.IsDir() {
					userDirs = append(userDirs, filepath.Join(homeBasePath, entry.Name()))
				}
			}
		}

		for _, userHome := range userDirs {
			fi, err := os.Stat(userHome)
			if err != nil || !fi.IsDir() {
				continue
			}

			// Regex filtering
			if compiledHomeRegex != nil && !compiledHomeRegex.MatchString(userHome) {
				logger.Printf("Skipping %s (does not match regex)", userHome)
				continue
			}

			user := filepath.Base(userHome)
			logger.Printf("Processing disk usage for user=%s (%s)", user, userHome)

			duOut, err := exec.Command("du", "-sb", userHome).Output()
			if err != nil {
				logger.Printf("Error running du for %s: %v", userHome, err)
				continue
			}

			parts := strings.Fields(string(duOut))
			if len(parts) >= 1 {
				bytesUsed, err := strconv.ParseInt(parts[0], 10, 64)
				if err == nil {
					diskUsage.WithLabelValues(user).Set(float64(bytesUsed))
					logger.Printf("Updated disk usage for user=%s → %d bytes", user, bytesUsed)
				} else {
					logger.Printf("Error parsing du output for %s: %v", userHome, err)
				}
			}
		}
	}
}

// Monitor User Idle Sessions
func monitorIdleSessions() {
	logger.Println("Starting idle session monitor...")

	ticker := time.NewTicker(15 * time.Second)

	idleThreshold := 300 * time.Second // 5 min idle → tuneable

	for {
		<-ticker.C

		sessionMutex.Lock()

		for user, sessions := range sessionState {
			// Optional: skip users not matching regex
			if !isUserMonitored(user) {
				continue
			}

			idleCount := 0

			for sessionID, startTime := range sessions {
				elapsed := time.Since(startTime)
				if elapsed > idleThreshold {
					idleCount++
					logger.Printf("Idle session detected: user=%s sessionID=%s idleFor=%.2f sec", user, sessionID, elapsed.Seconds())
				}
			}

			idleSessions.WithLabelValues(user).Set(float64(idleCount))
		}

		sessionMutex.Unlock()
	}
}

// Poll open files
func pollOpenFiles() {
	log.Printf("INFO: Starting open files polling")
	for {
		sessionMutex.Lock()
		out, err := runCommand("lsof", "-n", "+c", "0")
		if err == nil {
			log.Printf("DEBUG: Parsing open files")
			parseOpenFiles(out)
		} else {
			log.Printf("ERROR: Failed to run lsof: %v", err)
		}
		sessionMutex.Unlock()
		time.Sleep(10 * time.Second)
	}
}

// Parse Open Files
func parseOpenFiles(out string) {
	openFiles.Reset()
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		user := fields[2]
		openFiles.WithLabelValues(user).Inc()
	}
}

// Memory Usage metrics
func pollMemoryUsage() {
	log.Println("INFO: Starting memory usage polling")

	for {
		procs, err := os.ReadDir("/proc")
		if err != nil {
			log.Printf("ERROR: Failed to read /proc: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}

		memoryUsage.Reset()
		virtualMemoryUsage.Reset()
		memoryThresholdExceeded.Reset()

		for _, proc := range procs {
			if !proc.IsDir() || !isNumeric(proc.Name()) {
				continue
			}

			pid := proc.Name()
			statusFile := fmt.Sprintf("/proc/%s/status", pid)
			data, err := os.ReadFile(statusFile)
			if err != nil {
				continue
			}

			var uid, username string
			var rssKB, vmsizeKB int64 = -1, -1

			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				switch {
				case strings.HasPrefix(line, "Uid:"):
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						uid = fields[1]
					}
				case strings.HasPrefix(line, "VmRSS:"):
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						rssKB, _ = strconv.ParseInt(fields[1], 10, 64)
					}
				case strings.HasPrefix(line, "VmSize:"):
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						vmsizeKB, _ = strconv.ParseInt(fields[1], 10, 64)
					}
				}
			}

			// UID-based filtering
			uidInt, err := strconv.Atoi(uid)
			if err != nil || uidInt < *minValidUID {
				continue
			}

			if uid != "" && (rssKB > 0 || vmsizeKB > 0) {
				username = getUsernameFromUid(uid)
				if username == "" {
					username = "unknown"
				}

				if rssKB > 0 {
					usageBytes := float64(rssKB) * 1024
					memoryUsage.WithLabelValues(username).Add(usageBytes)

					if usageBytes > float64(*memoryThresholdBytes) {
						memoryThresholdExceeded.WithLabelValues(username).Set(1)
						log.Printf("🚨 Memory threshold exceeded: user=%s usage=%dMB", username, int(usageBytes/1024/1024))
					}
				}

				if vmsizeKB > 0 {
					virtualMemoryUsage.WithLabelValues(username).Add(float64(vmsizeKB) * 1024)
				}
			}
		}

		time.Sleep(10 * time.Second)
	}
}

// CPU Usage metrics
func pollCPUUsage() {
	log.Printf("INFO: Starting CPU usage polling")

	for {
		procs, err := os.ReadDir("/proc")
		if err != nil {
			log.Printf("ERROR: Failed to read /proc: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}

		cpu_Usage.Reset() // Reset the gauge for current polling interval

		for _, proc := range procs {
			if !proc.IsDir() || !isNumeric(proc.Name()) {
				continue
			}

			pid := proc.Name()
			statFile := fmt.Sprintf("/proc/%s/stat", pid)
			data, err := os.ReadFile(statFile)
			if err != nil {
				continue
			}

			fields := strings.Fields(string(data))
			if len(fields) < 17 {
				continue
			}

			utime, err1 := strconv.ParseFloat(fields[13], 64)
			stime, err2 := strconv.ParseFloat(fields[14], 64)
			if err1 != nil || err2 != nil {
				continue
			}

			uid := getUidFromProc(pid)
			username := getUsernameFromUid(uid)
			if username == "" {
				username = "unknown"
			}

			ticksPerSecond := 100.0 // Linux default
			totalCPU := (utime + stime) / ticksPerSecond

			cpu_Usage.WithLabelValues(username).Add(totalCPU)
		}

		time.Sleep(10 * time.Second)
	}
}

// Helper function for monitorIdleSessions

func isUserMonitored(user string) bool {
	if compiledHomeRegex == nil {
		return true // no regex → monitor all users
	}

	// Build the full path as it would appear in homeGlob
	userHome := filepath.Join(homeBasePath, user)

	return compiledHomeRegex.MatchString(userHome)
}

func runCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func getUidFromProc(pid string) string {
	statusFile := fmt.Sprintf("/proc/%s/status", pid)
	data, err := os.ReadFile(statusFile)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return fields[1] // real UID
			}
		}
	}
	return ""
}

func getUsernameFromUid(uid string) string {
	u, err := user.LookupId(uid)
	if err != nil {
		return ""
	}
	return u.Username
}

func isNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}
