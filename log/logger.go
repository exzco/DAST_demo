// Package log 提供封装后的日志输出服务，支持控制台打印开关，并同步持久化到本地 JSON 文件。
package log

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	mu           sync.Mutex
	printConsole = true // 开关，用于控制是否打印日志到终端
	logFilePath  = filepath.Join("log", "log_num.json")
)

// SetConsolePrint 设置是否在控制台/终端输出日志
func SetConsolePrint(enable bool) {
	mu.Lock()
	defer mu.Unlock()
	printConsole = enable
}

// LogEntry 定义日志持久化的 JSON 格式
type LogEntry struct {
	Time    string `json:"time"`
	Message string `json:"message"`
}

// Printf 包装 fmt.Printf 函数
func Printf(format string, v ...interface{}) {
	mu.Lock()
	defer mu.Unlock()

	msg := fmt.Sprintf(format, v...)

	// 1. 根据开关决定是否打印到终端
	if printConsole {
		fmt.Print(msg)
	}

	// 2. 无论开关如何，都打印到 log 文件夹下的 log_num.json
	_ = os.MkdirAll("log", 0755)

	entry := LogEntry{
		Time:    time.Now().Format(time.RFC3339),
		Message: strings.TrimRight(msg, "\n"),
	}

	data, err := json.Marshal(entry)
	if err == nil {
		// 使用 O_APPEND 原子追加写入，确保多线程写入时的安全
		f, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			_, _ = f.Write(append(data, '\n'))
			_ = f.Close()
		}
	}
}

// Println 包装 fmt.Println 函数
func Println(v ...interface{}) {
	msg := fmt.Sprintln(v...)
	Printf("%s", msg)
}
