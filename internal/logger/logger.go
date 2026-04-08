package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// Level represents the log level
type Level int

const (
	DebugLevel Level = iota
	InfoLevel
	WarnLevel
	ErrorLevel
)

func (l Level) String() string {
	switch l {
	case DebugLevel:
		return "DEBUG"
	case InfoLevel:
		return "INFO"
	case WarnLevel:
		return "WARN"
	case ErrorLevel:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// Entry represents a structured log entry
type Entry struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Component string                 `json:"component,omitempty"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
	Error     string                 `json:"error,omitempty"`
}

// Logger provides structured logging
type Logger struct {
	out       io.Writer
	level     Level
	jsonMode  bool
	component string
	mu        sync.Mutex
}

// NewLogger creates a new logger
func NewLogger(out io.Writer, level Level, jsonMode bool) *Logger {
	return &Logger{
		out:      out,
		level:    level,
		jsonMode: jsonMode,
	}
}

// WithComponent returns a logger with a component name
func (l *Logger) WithComponent(component string) *Logger {
	newLogger := *l
	newLogger.component = component
	return &newLogger
}

// log writes a log entry
func (l *Logger) log(level Level, msg string, err error, fields map[string]interface{}) {
	if level < l.level {
		return
	}

	entry := Entry{
		Timestamp: time.Now(),
		Level:     level.String(),
		Message:   msg,
		Component: l.component,
		Fields:    fields,
	}

	if err != nil {
		entry.Error = err.Error()
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.jsonMode {
		data, _ := json.Marshal(entry)
		fmt.Fprintln(l.out, string(data))
	} else {
		timeStr := entry.Timestamp.Format("2006-01-02T15:04:05.000Z07:00")
		component := entry.Component
		if component == "" {
			component = "exporter"
		}
		errStr := ""
		if entry.Error != "" {
			errStr = fmt.Sprintf(" error=%s", entry.Error)
		}
		fmt.Fprintf(l.out, "%s [%s] %s: %s%s\n", timeStr, entry.Level, component, entry.Message, errStr)
	}
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(DebugLevel, msg, nil, f)
}

// Info logs an info message
func (l *Logger) Info(msg string, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(InfoLevel, msg, nil, f)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, err error, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(WarnLevel, msg, err, f)
}

// Error logs an error message
func (l *Logger) Error(msg string, err error, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(ErrorLevel, msg, err, f)
}

// Debugf logs a formatted debug message
func (l *Logger) Debugf(format string, args ...interface{}) {
	l.Debug(fmt.Sprintf(format, args...))
}

// Infof logs a formatted info message
func (l *Logger) Infof(format string, args ...interface{}) {
	l.Info(fmt.Sprintf(format, args...))
}

// Warnf logs a formatted warning message
func (l *Logger) Warnf(format string, args ...interface{}) {
	l.Warn(fmt.Sprintf(format, args...), nil)
}

// Errorf logs a formatted error message
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.Error(fmt.Sprintf(format, args...), nil)
}
