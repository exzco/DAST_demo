//	dast-engine dispatch  -task t001 -ips "192.168.1.1 10.0.0.1" -ports top1000
//	dast-engine port-worker
//	dast-engine fp-worker
//	dast-engine poc-worker
//	dast-engine all

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"distributed-scanner/internal/config"
	"distributed-scanner/internal/fingerprint"
	"distributed-scanner/internal/models"
	"distributed-scanner/internal/poc"
	"distributed-scanner/internal/portscan"
	"distributed-scanner/internal/queue"
	log "distributed-scanner/log"
)

// Stage-1 Dispatcher：将 IP 列表拆分为 PortJob 推入队列

func runDispatcher(cfg *config.Config, args []string) {
	startTime := time.Now()
	fs := flag.NewFlagSet("dispatch", flag.ExitOnError)
	taskId := fs.String("task", "", "任务 ID（必填）")
	ipsFlag := fs.String("ips", "", "空格分隔的 IP 列表，例：192.168.1.1 10.0.0.1")
	fileFlag := fs.String("file", "", "IP 列表文件（每行一个 IP）")
	// 默认值留空，以便区分「用户显式指定」和「未指定」两种情况
	ports := fs.String("ports", "", "端口范围: top1000 / full / 80,443,8080（不填时优先使用 IP 内嵌端口，否则使用默认值）")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "用法: dast-engine dispatch -task <id> [-ips <ip,...>] [-file <path>] [-ports <range>]")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	if *taskId == "" {
		fmt.Fprintln(os.Stderr, "错误：缺少 -task 参数")
		fs.Usage()
		os.Exit(1)
	}

	var ips []string
	if *ipsFlag != "" {
		for _, ip := range strings.Split(*ipsFlag, " ") {
			if ip = strings.TrimSpace(ip); ip != "" {
				ips = append(ips, ip)
			}
		}
	}
	if *fileFlag != "" {
		ips = append(ips, readLines(*fileFlag)...)
	}
	if len(ips) == 0 {
		fmt.Fprintln(os.Stderr, "错误：请用 -ips 或 -file 提供 IP 列表")
		os.Exit(1)
	}

	rdb := queue.NewClient(cfg.Redis)
	ctx := context.Background()

	// 清空可能存在的前一次同名任务残留数据
	rdb.Del(ctx, cfg.Queue.StatusKey(*taskId), cfg.Queue.ResultsKey(*taskId))

	rdb.HSet(ctx, cfg.Queue.StatusKey(*taskId),
		"status", "running",
		"total_ips", len(ips),
		"started_at", time.Now().Format(time.RFC3339),
	)

	for i, rawIP := range ips {
		// 解析端口优先级：-ports flag > IP 内嵌端口（host:port）> 配置默认值
		jobIP := rawIP
		jobPorts := *ports

		if host, portStr, err := net.SplitHostPort(rawIP); err == nil {
			// IP 带有内嵌端口，如 127.0.0.1:8088 或 [::1]:8088
			jobIP = host
			if jobPorts == "" {
				// 用户未显式指定 -ports，使用 IP 内嵌端口
				jobPorts = portStr
			}
		}

		if jobPorts == "" {
			// 既没有 -ports，也没有内嵌端口，使用配置默认值
			jobPorts = cfg.Scan.DefaultPorts
		}

		job := models.PortJob{
			TaskId: *taskId,
			IP:     jobIP,
			Ports:  jobPorts,
		}
		data, _ := json.Marshal(job)
		if err := rdb.Push(ctx, cfg.Queue.PortJobs(), string(data)); err != nil {
			fmt.Fprintf(os.Stderr, "[dispatcher] push failed ip=%s: %v\n", rawIP, err)
			continue
		}
		log.Printf("[dispatcher] [%d/%d] queued ip=%s ports=%s\n", i+1, len(ips), jobIP, jobPorts)
	}

	log.Printf("[dispatcher] done: taskId=%s, %d IPs pushed to %s, cost=%s\n", *taskId, len(ips), cfg.Queue.PortJobs(), time.Since(startTime))
	log.Printf("[dispatcher] monitor(当前任务状态查看) : redis-cli hgetall %s\n", cfg.Queue.StatusKey(*taskId))
	log.Printf("[dispatcher] results(当前任务结果查看) : redis-cli lrange  %s 0 -1\n", cfg.Queue.ResultsKey(*taskId))
}

// Stage-2 Port-Worker：端口扫描（naabu）

func runPortWorker(ctx context.Context, cfg *config.Config) {
	rdb := queue.NewClient(cfg.Redis)
	startControlListener(ctx, rdb)

	hostname, _ := os.Hostname()
	log.Printf("[port-worker] started on %s, redis=%s\n", hostname, cfg.Redis.Addr)
	log.Printf("[port-worker] waiting for jobs on %s ...\n", cfg.Queue.PortJobs())

	for {
		select {
		case <-ctx.Done():
			log.Println("[port-worker] shutting down")
			return
		default:
		}

		raw, err := rdb.BLPop(ctx, cfg.Queue.PortJobs())
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("[port-worker] blpop error: %v\n", err)
			continue
		}

		var job models.PortJob
		if err := json.Unmarshal([]byte(raw), &job); err != nil {
			log.Printf("[port-worker] invalid job: %v\n", err)
			continue
		}

		log.Printf("[port-worker] scanning taskId=%s ip=%s\n", job.TaskId, job.IP)

		startTime := time.Now()
		openPorts, err := portscan.ScanIP(ctx, job.IP, job.Ports, cfg.PortScan)
		duration := time.Since(startTime)
		if err != nil {
			log.Printf("[port-worker] scan failed ip=%s err=%v, cost=%s\n", job.IP, err, duration)
		}

		// 防止 job.IP 含内嵌端口如 "127.0.0.1:8088"，导致 FpJob.Host 再拼 port 后出现双冒号 "127.0.0.1:8088:8088"
		scanHost := job.IP
		if h, _, err := net.SplitHostPort(job.IP); err == nil {
			scanHost = h
		}

		for _, port := range openPorts {
			fpJob := models.FpJob{
				TaskId: job.TaskId,
				Host:   scanHost,
				Port:   port,
			}
			data, _ := json.Marshal(fpJob)

			rdb.Push(ctx, cfg.Queue.FpJobs(), string(data))
		}

		rdb.HIncrBy(ctx, cfg.Queue.StatusKey(job.TaskId), "scanned_ips", 1)
		rdb.HIncrBy(ctx, cfg.Queue.StatusKey(job.TaskId), "open_ports", int64(len(openPorts)))
		log.Printf("[port-worker] done ip=%s open=%d ports, pushed to %s, cost=%s\n",
			job.IP, len(openPorts), cfg.Queue.FpJobs(), duration)

		// Save detailed open ports to result/result.json
		saveResult(job.TaskId, "port_scan", struct {
			IP    string `json:"ip"`
			Ports []int  `json:"ports"`
		}{
			IP:    scanHost,
			Ports: openPorts,
		})
	}
}

// Stage-3b FP-Worker：TCP/协议指纹识别（fingerprintx）

func runFpWorker(ctx context.Context, cfg *config.Config) {
	rdb := queue.NewClient(cfg.Redis)
	startControlListener(ctx, rdb)

	hostname, _ := os.Hostname()
	log.Printf("[fp-worker] started on %s, redis=%s\n", hostname, cfg.Redis.Addr)
	log.Printf("[fp-worker] waiting for jobs on %s ...\n", cfg.Queue.FpJobs())

	for {
		select {
		case <-ctx.Done():
			log.Println("[fp-worker] shutting down")
			return
		default:
		}

		raw, err := rdb.BLPop(ctx, cfg.Queue.FpJobs())
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("[fp-worker] blpop error: %v\n", err)
			continue
		}

		var job models.FpJob
		if err := json.Unmarshal([]byte(raw), &job); err != nil {
			log.Printf("[fp-worker] invalid job: %v\n", err)
			continue
		}

		if isTaskCancelled(job.TaskId) {
			log.Printf("[fp-worker] skipped job for cancelled taskId=%s\n", job.TaskId)
			continue
		}

		log.Printf("[fp-worker] probing taskId=%s host=%s port=%d\n", job.TaskId, job.Host, job.Port)

		startTime := time.Now()
		// 使用 nmap -sV 进行服务版本识别，替代原手写 Banner/HTTP 规则探测
		result, err := fingerprint.NmapProbe(ctx, job.Host, job.Port)
		duration := time.Since(startTime)
		if err != nil {
			isTimeout := strings.Contains(err.Error(), "timed out") || strings.Contains(err.Error(), "deadline exceeded")
			if isTimeout {
				log.Printf("[fp-worker] nmap-probe timed out on %s:%d (likely filtered or firewall blocked). Skipping retry. cost=%s\n", job.Host, job.Port, duration)
				result = fingerprint.ProbeResult{
					URL:         fmt.Sprintf("%s:%d", job.Host, job.Port),
					Proto:       "tcp",
					Tags:        fingerprint.FallbackTags,
					RawResponse: fmt.Sprintf("nmap probe timed out: %v", err),
				}
			} else {
				if job.Retry < 3 {
					job.Retry++
					job.FailReason = fmt.Sprintf("retry %d/3: %v", job.Retry, err)
					data, _ := json.Marshal(job)
					rdb.Push(ctx, cfg.Queue.FpJobs(), string(data))
					log.Printf("[fp-worker] nmap-probe error on %s:%d, retrying (%d/3): %v, cost=%s\n", job.Host, job.Port, job.Retry, err, duration)
					continue
				}
				log.Printf("[fp-worker] nmap-probe error on %s:%d, max retries reached: %v. falling back to default tags. cost=%s\n", job.Host, job.Port, err, duration)
				result = fingerprint.ProbeResult{
					URL:         fmt.Sprintf("%s:%d", job.Host, job.Port),
					Proto:       "tcp",
					Tags:        fingerprint.FallbackTags,
					RawResponse: fmt.Sprintf("nmap probe failed: %v", err),
				}
			}
		} else {
			if len(result.Tags) == 0 {
				result.Tags = fingerprint.FallbackTags
				log.Printf("[fp-worker] no fingerprint matched for %s:%d (proto=%s), using fallback tags\n",
					job.Host, job.Port, result.Proto)
				rdb.HIncrBy(ctx, cfg.Queue.StatusKey(job.TaskId), "fp_fallback", 1)
			}
		}

		pocJob := models.PocJob{
			TaskId: job.TaskId,
			Target: result.URL,
			Proto:  result.Proto,
			Tags:   result.Tags,
			Retry:  0,
		}

		data, _ := json.Marshal(pocJob)
		rdb.Push(ctx, cfg.Queue.PocJobs(), string(data))

		rdb.HIncrBy(ctx, cfg.Queue.StatusKey(job.TaskId), "fp_done", 1)
		log.Printf("[fp-worker] done host=%s:%d → target=%s tags=%v, cost=%s\n",
			job.Host, job.Port, result.URL, result.Tags, duration)

		// Save fingerprint metadata to result/result.json
		isFallback := len(result.Tags) == 3 && result.Tags[0] == "exposure" && result.Tags[1] == "misconfig" && result.Tags[2] == "config"
		if isFallback {
			saveResult(job.TaskId, "fingerprint", struct {
				Host     string   `json:"host"`
				Port     int      `json:"port"`
				Proto    string   `json:"proto"`
				Tags     []string `json:"tags"`
				Response string   `json:"response"`
			}{
				Host:     job.Host,
				Port:     job.Port,
				Proto:    result.Proto,
				Tags:     result.Tags,
				Response: result.RawResponse,
			})
		} else {
			saveResult(job.TaskId, "fingerprint", struct {
				Host  string   `json:"host"`
				Port  int      `json:"port"`
				Proto string   `json:"proto"`
				Tags  []string `json:"tags"`
			}{
				Host:  job.Host,
				Port:  job.Port,
				Proto: result.Proto,
				Tags:  result.Tags,
			})
		}
	}
}

// Stage-4 POC-Worker：nuclei 按指纹 tags 匹配 POC 模板进行漏洞验证

func runPocWorker(ctx context.Context, cfg *config.Config) {
	rdb := queue.NewClient(cfg.Redis)
	startControlListener(ctx, rdb)

	hostname, _ := os.Hostname()
	log.Printf("[poc-worker] started on %s, redis=%s\n", hostname, cfg.Redis.Addr)
	log.Printf("[poc-worker] waiting for jobs on %s ...\n", cfg.Queue.PocJobs())

	for {
		select {
		case <-ctx.Done():
			log.Println("[poc-worker] shutting down")
			return
		default:
		}

		raw, err := rdb.BLPop(ctx, cfg.Queue.PocJobs())
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("[poc-worker] blpop error: %v\n", err)
			continue
		}

		var job models.PocJob
		if err := json.Unmarshal([]byte(raw), &job); err != nil {
			log.Printf("[poc-worker] invalid job: %v\n", err)
			continue
		}

		if isTaskCancelled(job.TaskId) {
			log.Printf("[poc-worker] skipped job for cancelled taskId=%s\n", job.TaskId)
			continue
		}

		log.Printf("[poc-worker] scanning taskId=%s target=%s tags=%v\n",
			job.TaskId, job.Target, job.Tags)

		startTime := time.Now()
		findings, err := poc.ScanWithTags(ctx, job.Target, job.Tags, cfg.Scan.PocDir)
		duration := time.Since(startTime)

		if err != nil {
			log.Printf("[poc-worker] scan failed target=%s: %v, cost=%s\n",
				job.Target, err, duration)
			rdb.HIncrBy(ctx, cfg.Queue.StatusKey(job.TaskId), "poc_done", 1)
			continue
		}

		for _, f := range findings {
			b, _ := json.Marshal(f)
			rdb.Push(ctx, cfg.Queue.ResultsKey(job.TaskId), string(b))
			log.Printf("[poc-worker] FINDING taskId=%s template=%s severity=%s matched=%s\n",
				job.TaskId, f.TemplateID, f.Severity, f.Matched)
			saveResult(job.TaskId, "poc_finding", f)
		}

		rdb.HIncrBy(ctx, cfg.Queue.StatusKey(job.TaskId), "poc_done", 1)
		rdb.HIncrBy(ctx, cfg.Queue.StatusKey(job.TaskId), "findings", int64(len(findings)))
		log.Printf("[poc-worker] done target=%s findings=%d cost=%s\n",
			job.Target, len(findings), duration)

		saveResult(job.TaskId, "poc_scan", struct {
			Target   string   `json:"target"`
			Tags     []string `json:"tags"`
			Findings int      `json:"findings"`
		}{
			Target:   job.Target,
			Tags:     job.Tags,
			Findings: len(findings),
		})
	}
}

// all：本地联调模式，同时启动所有 worker

func runAll(cfg *config.Config, args []string) {
	fs := flag.NewFlagSet("all", flag.ExitOnError)
	portN := fs.Int("port-workers", 5, "port-worker 并发数")
	fpN := fs.Int("fp-workers", 5, "fp-worker 并发数")
	pocN := fs.Int("poc-workers", 5, "poc-worker 并发数")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "用法: dast-engine all [-port-workers N] [-fp-workers N] [-poc-workers N]")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var wg sync.WaitGroup

	start := func(name string, n int, fn func(context.Context, *config.Config)) {
		for i := 0; i < n; i++ {
			wg.Add(1)
			idx := i + 1
			go func() {
				defer wg.Done()
				log.Printf("[all] starting %s #%d\n", name, idx)
				fn(ctx, cfg)
			}()
		}
	}

	start("port-worker", *portN, runPortWorker)
	// start("http-worker", *httpN, runHttpWorker)
	start("fp-worker", *fpN, runFpWorker)
	start("poc-worker", *pocN, runPocWorker)

	log.Printf("[all] pipeline started: port×%d + fp×%d + poc×%d\n",
		*portN, *fpN, *pocN)
	log.Println("[all] press Ctrl+C to stop all workers")

	wg.Wait()
	log.Println("[all] all workers stopped")
}

// 主入口

func usage() {
	fmt.Fprintf(os.Stderr, `
用法:
  dast-engine <subcommand> [flags]

子命令:
  dispatch     投递扫描任务
               -task <id>   任务 ID
               -ips  <ips>  空格分隔的 IP 列表
               -file <path> IP 列表文件
               -ports <r>   端口范围: top1000 / full / 80,443

  port-worker  端口扫描 Worker
  fp-worker    TCP/协议指纹 Worker
  poc-worker   POC 漏洞扫描 Worker

  worker       一键启动所有 worker (port-worker, fp-worker, poc-worker)
               -port-workers N   （默认 2）
               -fp-workers   N   （默认 1）
               -poc-workers  N   （默认 1）

  all          一键启动所有 worker (worker 的别名)

环境变量（所有配置通过环境变量注入，无需修改代码）:
  REDIS_ADDR          Redis 地址                （默认 127.0.0.1:6379）
  REDIS_PASSWORD      Redis 密码                （默认 空，生产环境建议设置）
  REDIS_DB            Redis 数据库编号           （默认 0）
  REDIS_DIAL_TIMEOUT  连接超时秒数               （默认 5）
  REDIS_READ_TIMEOUT  阻塞读超时秒数             （默认 60）
  POC_DIR             nuclei 模板目录            （默认 ./poc）
  DEFAULT_PORTS       默认端口范围               （默认 top1000）
  QUEUE_PREFIX        队列键前缀，用于多环境隔离  （默认 scan）
  PORTSCAN_RATE       naabu 发包速率 pps         （默认 1000）
  PORTSCAN_TIMEOUT    naabu 单端口超时秒数        （默认 5）
  PORTSCAN_THREADS    naabu 并发线程数            （默认 25）

示例:
  # 投递任务
  REDIS_ADDR=10.0.0.1:6379 REDIS_PASSWORD=secret \
    dast-engine dispatch -task t001 -ips "192.168.1.1 10.0.0.1"

  # 单独启动 worker
  REDIS_ADDR=10.0.0.1:6379 REDIS_PASSWORD=secret dast-engine port-worker

  # 本地联调（全部启动）
  REDIS_ADDR=127.0.0.1:6379 POC_DIR=./poc dast-engine all

  # 查看生效配置
  REDIS_ADDR=10.0.0.1:6379 REDIS_PASSWORD=secret dast-engine config
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("\n[engine] Received interrupt signal (Ctrl+C), exiting immediately...")
		os.Exit(0)
	}()

	cfg := config.Load()
	log.SetConsolePrint(cfg.ConsoleLog)

	subCmd := os.Args[1]
	rest := os.Args[2:]

	// 指纹规则已由 nmap -sV 替代，无需加载自定义规则文件

	switch subCmd {
	case "dispatch":
		runDispatcher(cfg, rest)

	case "port-worker":
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		runPortWorker(ctx, cfg)

	case "fp-worker":
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		runFpWorker(ctx, cfg)

	case "poc-worker":
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		runPocWorker(ctx, cfg)

	case "worker", "all":
		runAll(cfg, rest)

	case "config":
		// 打印当前生效配置（敏感字段脱敏），便于运维排查
		cfg.Print()

	case "help", "-h", "--help":
		usage()

	default:
		fmt.Fprintf(os.Stderr, "未知子命令: %q\n\n", subCmd)
		usage()
		os.Exit(1)
	}
}

func readLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open file failed: %v\n", err)
		return nil
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "[readLines] scanner error: %v\n", err)
	}
	return lines
}

var (
	cancelledTasks   = make(map[string]bool)
	cancelledTasksMu sync.RWMutex
)

func isTaskCancelled(taskId string) bool {
	cancelledTasksMu.RLock()
	defer cancelledTasksMu.RUnlock()
	return cancelledTasks[taskId]
}

func cancelTask(taskId string) {
	cancelledTasksMu.Lock()
	defer cancelledTasksMu.Unlock()
	cancelledTasks[taskId] = true
}

func startControlListener(ctx context.Context, rdb *queue.Client) {
	pubsub := rdb.Subscribe(ctx, "scan:control")
	go func() {
		defer pubsub.Close()
		ch := pubsub.Channel()
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-ch:
				if !ok {
					return
				}
				taskId := strings.TrimSpace(msg.Payload)
				if taskId != "" {
					cancelTask(taskId)
					log.Printf("[control] Task %s cancellation received via Pub/Sub. Skipping future jobs for this task.\n", taskId)
				}
			}
		}
	}()
}

var resultFileMu sync.Mutex

func saveResult(taskId, entryType string, data interface{}) {
	resultFileMu.Lock()
	defer resultFileMu.Unlock()

	_ = os.MkdirAll("result", 0755)

	entry := struct {
		TaskId    string      `json:"taskId"`
		Type      string      `json:"type"`
		Timestamp string      `json:"timestamp"`
		Data      interface{} `json:"data"`
	}{
		TaskId:    taskId,
		Type:      entryType,
		Timestamp: time.Now().Format(time.RFC3339),
		Data:      data,
	}

	b, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		log.Printf("[result-save] marshal failed: %v\n", err)
		return
	}

	f, err := os.OpenFile(filepath.Join("result", "result.json"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[result-save] open file failed: %v\n", err)
		return
	}
	defer f.Close()

	_, _ = f.Write(append(b, []byte("\n\n")...))
}
