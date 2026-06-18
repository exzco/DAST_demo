// Package config 集中管理所有运行时配置
//
//	cfg := config.Load()        // 在 main() 入口调用一次
//	rdb := queue.NewClient(cfg) // 将 cfg 传入各子系统
package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	log "distributed-scanner/log"
)

// Config 是整个引擎的运行时配置，由环境变量填充，启动时加载一次后只读使用。
type Config struct {
	Redis      RedisConfig
	Scan       ScanConfig
	Queue      QueueKeys
	PortScan   PortScanConfig
	ConsoleLog bool
}

type RedisConfig struct {
	Addr        string
	Password    string
	DB          int
	DialTimeout time.Duration
	ReadTimeout time.Duration
}

type ScanConfig struct {
	// POC_DIR: nuclei 模板目录路径
	// 默认：./poc（仅本地开发）
	PocDir       string
	DefaultPorts string
	FpRulesFile  string // 指纹规则 JSON 文件路径
}

type QueueKeys struct {
	Prefix string
}

func (q QueueKeys) PortJobs() string { return q.Prefix + ":port:jobs" }

func (q QueueKeys) HttpJobs() string { return q.Prefix + ":http:jobs" }

func (q QueueKeys) FpJobs() string { return q.Prefix + ":fp:jobs" }

func (q QueueKeys) PocJobs() string { return q.Prefix + ":poc:jobs" }

func (q QueueKeys) StatusKey(taskId string) string { return q.Prefix + ":status:" + taskId }

func (q QueueKeys) ResultsKey(taskId string) string { return q.Prefix + ":results:" + taskId }

type PortScanConfig struct {
	// PORTSCAN_RATE: 每秒发包速率
	// 默认：1000
	Rate int

	// PORTSCAN_TIMEOUT: 单端口探测超时（秒）
	// 默认：5
	Timeout time.Duration

	// PORTSCAN_THREADS: 并发线程数
	// 默认：25
	Threads int

	// PORTSCAN_TYPE: "connect" (TCP Connect 扫描) 或 "syn" (TCP SYN 扫描)
	// 默认："connect"
	ScanType string
}

func Load() *Config {
	cfg := &Config{
		Redis: RedisConfig{
			Addr:        mustEnv("REDIS_ADDR", "127.0.0.1:6379"),
			Password:    getEnv("REDIS_PASSWORD"),
			DB:          envInt("REDIS_DB", 0),
			DialTimeout: envDuration("REDIS_DIAL_TIMEOUT", 5) * time.Second,
			ReadTimeout: envDuration("REDIS_READ_TIMEOUT", 60) * time.Second,
		},
		Scan: ScanConfig{
			PocDir:       mustEnv("POC_DIR", "./poc"),
			DefaultPorts: mustEnv("DEFAULT_PORTS", "top1000"),
			FpRulesFile:  mustEnv("FP_RULES_FILE", "./fingerprints.json"),
		},
		Queue: QueueKeys{
			Prefix: mustEnv("QUEUE_PREFIX", "scan"),
		},
		PortScan: PortScanConfig{
			Rate:     envInt("PORTSCAN_RATE", 1000),
			Timeout:  envDuration("PORTSCAN_TIMEOUT", 5) * time.Second,
			Threads:  envInt("PORTSCAN_THREADS", 25),
			ScanType: mustEnv("PORTSCAN_TYPE", "connect"),
		},
		ConsoleLog: envBool("CONSOLE_LOG", true),
	}
	return cfg
}

func (c *Config) Print() {
	redacted := "（未设置）"
	if c.Redis.Password != "" {
		redacted = "***（已设置）"
	}
	log.Printf("[config] Redis.Addr        = %s\n", c.Redis.Addr)
	log.Printf("[config] Redis.Password    = %s\n", redacted)
	log.Printf("[config] Redis.DB          = %d\n", c.Redis.DB)
	log.Printf("[config] Redis.DialTimeout = %s\n", c.Redis.DialTimeout)
	log.Printf("[config] Redis.ReadTimeout = %s\n", c.Redis.ReadTimeout)
	log.Printf("[config] Scan.PocDir       = %s\n", c.Scan.PocDir)
	log.Printf("[config] Scan.DefaultPorts = %s\n", c.Scan.DefaultPorts)
	log.Printf("[config] Scan.FpRulesFile  = %s\n", c.Scan.FpRulesFile)
	log.Printf("[config] Queue.Prefix      = %s\n", c.Queue.Prefix)
	log.Printf("[config] PortScan.Rate     = %d pps\n", c.PortScan.Rate)
	log.Printf("[config] PortScan.Timeout  = %s\n", c.PortScan.Timeout)
	log.Printf("[config] PortScan.Threads  = %d\n", c.PortScan.Threads)
	log.Printf("[config] PortScan.ScanType = %s\n", c.PortScan.ScanType)
	log.Printf("[config] ConsoleLog        = %t\n", c.ConsoleLog)
}

var envMap map[string]string

func init() {
	envMap = loadDotEnv(".env")
}

func loadDotEnv(filenames ...string) map[string]string {
	m := make(map[string]string)
	for _, filename := range filenames {
		f, err := os.Open(filename)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])

			// Remove quotes if present
			if len(val) >= 2 {
				if (val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'') {
					val = val[1 : len(val)-1]
				}
			}
			m[key] = val
		}
		f.Close()
	}
	return m
}

func getEnv(key string) string {
	if v, exists := envMap[key]; exists {
		return v
	}
	return os.Getenv(key)
}

func mustEnv(key, def string) string {
	if v := getEnv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := getEnv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
		fmt.Fprintf(os.Stderr, "[config] 警告：%s 值 %q 不是有效整数，使用默认值 %d\n", key, v, def)
	}
	return def
}

func envDuration(key string, defSec int) time.Duration {
	if v := getEnv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return time.Duration(n)
		}
		fmt.Fprintf(os.Stderr, "[config] 警告：%s 值 %q 不是有效整数，使用默认值 %ds\n", key, v, defSec)
	}
	return time.Duration(defSec)
}

func envBool(key string, def bool) bool {
	if v := getEnv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}
