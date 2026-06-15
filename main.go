// DAST 扫描引擎入口
//
//	dast-engine dispatch  -task t001 -ips "192.168.1.1 10.0.0.1" -ports top1000
//	dast-engine port-worker
//	dast-engine http-worker
//	dast-engine fp-worker
//	dast-engine poc-worker
//	dast-engine all       

package mai

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"distributed-scanner/internal/config"
	"distributed-scanner/internal/fingerprint"
	"distributed-scanner/internal/httpfp"
	"distributed-scanner/internal/models"
	"distributed-scanner/internal/poc"
	"distributed-scanner/internal/portscan"
	"distributed-scanner/internal/queue"
)

// ─────────────────────────────────────────────────────────────────────────────
// 工具函数
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// Stage-1 Dispatcher：将 IP 列表拆分为 PortJob 推入队列
// ─────────────────────────────────────────────────────────────────────────────

func runDispatcher(cfg *config.Config, args []string) {
	fs := flag.NewFlagSet("dispatch", flag.ExitOnError)
	taskId := fs.String("task", "", "任务 ID（必填）")
	ipsFlag := fs.String("ips", "", "空格分隔的 IP 列表，例：192.168.1.1 10.0.0.1")
	fileFlag := fs.String("file", "", "IP 列表文件（每行一个 IP）")
	ports := fs.String("ports", cfg.Scan.DefaultPorts, "端口范围: top1000 / full / 80,443,8080")
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

	// 记录任务元信息（供监控查看）
	rdb.HSet(ctx, cfg.Queue.StatusKey(*taskId),
		"status", "running",
		"total_ips", len(ips),
		"ports", *ports,
		"started_at", time.Now().Format(time.RFC3339),
	)

	for i, ip := range ips {
		job := models.PortJob{
			TaskId: *taskId,
			IP:     ip,
			Ports:  *ports,
		}
		data, _ := json.Marshal(job)
		if err := rdb.Push(ctx, cfg.Queue.PortJobs(), string(data)); err != nil {
			fmt.Fprintf(os.Stderr, "[dispatcher] push failed ip=%s: %v\n", ip, err)
			continue
		}
		fmt.Printf("[dispatcher] [%d/%d] queued ip=%s\n", i+1, len(ips), ip)
	}

	fmt.Printf("[dispatcher] done: taskId=%s, %d IPs pushed to %s\n", *taskId, len(ips), cfg.Queue.PortJobs())
	fmt.Printf("[dispatcher] monitor : redis-cli hgetall %s\n", cfg.Queue.StatusKey(*taskId))
	fmt.Printf("[dispatcher] results : redis-cli lrange  %s 0 -1\n", cfg.Queue.ResultsKey(*taskId))
}

// ─────────────────────────────────────────────────────────────────────────────
// Stage-2 Port-Worker：端口扫描（naabu）
// ─────────────────────────────────────────────────────────────────────────────

func runPortWorker(ctx context.Context, cfg *config.Config) {
	rdb := queue.NewClient(cfg.Redis)

	hostname, _ := os.Hostname()
	fmt.Printf("[port-worker] started on %s, redis=%s\n", hostname, cfg.Redis.Addr)
	fmt.Printf("[port-worker] waiting for jobs on %s ...\n", cfg.Queue.PortJobs())

	for {
		select {
		case <-ctx.Done():
			fmt.Println("[port-worker] shutting down")
			return
		default:
		}

		raw, err := rdb.BLPop(ctx, cfg.Queue.PortJobs())
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			fmt.Printf("[port-worker] blpop error: %v\n", err)
			continue
		}

		var job models.PortJob
		if err := json.Unmarshal([]byte(raw), &job); err != nil {
			fmt.Printf("[port-worker] invalid job: %v\n", err)
			continue
		}

		fmt.Printf("[port-worker] scanning taskId=%s ip=%s\n", job.TaskId, job.IP)

		openPorts, err := portscan.ScanIP(ctx, job.IP, job.Ports, cfg.PortScan)
		if err != nil {
			fmt.Printf("[port-worker] scan failed ip=%s err=%v\n", job.IP, err)
		}

		for _, port := range openPorts {
			httpJob := models.HttpJob{
				TaskId: job.TaskId,
				Host:   job.IP,
				Port:   port,
			}
			data, _ := json.Marshal(httpJob)
			
			rdb.Push(ctx, cfg.Queue.HttpJobs(), string(data))
		}

		rdb.HIncrBy(ctx, cfg.Queue.StatusKey(job.TaskId), "scanned_ips", 1)
		rdb.HIncrBy(ctx, cfg.Queue.StatusKey(job.TaskId), "open_ports", int64(len(openPorts)))
		fmt.Printf("[port-worker] done ip=%s open=%d ports, pushed to %s\n",
			job.IP, len(openPorts), cfg.Queue.HttpJobs())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Stage-3 HTTP-Worker：HTTP 指纹识别（httpx + wappalyzer）
// ─────────────────────────────────────────────────────────────────────────────

func runHttpWorker(ctx context.Context, cfg *config.Config) {
	rdb := queue.NewClient(cfg.Redis)

	hostname, _ := os.Hostname()
	fmt.Printf("[http-worker] started on %s, redis=%s\n", hostname, cfg.Redis.Addr)
	fmt.Printf("[http-worker] waiting for jobs on %s ...\n", cfg.Queue.HttpJobs())

	for {
		select {
		case <-ctx.Done():
			fmt.Println("[http-worker] shutting down")
			return
		default:
		}

		raw, err := rdb.BLPop(ctx, cfg.Queue.HttpJobs())
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			fmt.Printf("[http-worker] blpop error: %v\n", err)
			continue
		}

		var job models.HttpJob
		if err := json.Unmarshal([]byte(raw), &job); err != nil {
			fmt.Printf("[http-worker] invalid job: %v\n", err)
			continue
		}

		fmt.Printf("[http-worker] probing taskId=%s host=%s port=%d\n", job.TaskId, job.Host, job.Port)

		result, err := httpfp.Probe(job.Host, job.Port)
		if err != nil {
			fmt.Printf("[http-worker] probe error host=%s:%d err=%v\n", job.Host, job.Port, err)
			// 探测失败也推入 poc 队列（使用兜底 tags），不完全跳过
			result = &httpfp.FpResult{
				URL:   fmt.Sprintf("%s:%d", job.Host, job.Port),
				Proto: "tcp",
				Tags:  []string{"network", "exposure"},
			}
		}

		pocJob := models.PocJob{
			TaskId: job.TaskId,
			Target: result.URL,
			Proto:  result.Proto,
			Tags:   result.Tags,
		}

		data, _ := json.Marshal(pocJob)
		rdb.Push(ctx, cfg.Queue.PocJobs(), string(data))

		rdb.HIncrBy(ctx, cfg.Queue.StatusKey(job.TaskId), "http_done", 1)
		fmt.Printf("[http-worker] done host=%s:%d → url=%s tags=%v\n",
			job.Host, job.Port, result.URL, result.Tags)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Stage-3b FP-Worker：TCP/协议指纹识别（fingerprintx）
// ─────────────────────────────────────────────────────────────────────────────

func runFpWorker(ctx context.Context, cfg *config.Config) {
	rdb := queue.NewClient(cfg.Redis)

	hostname, _ := os.Hostname()
	fmt.Printf("[fp-worker] started on %s, redis=%s\n", hostname, cfg.Redis.Addr)
	fmt.Printf("[fp-worker] waiting for jobs on %s ...\n", cfg.Queue.FpJobs())

	for {
		select {
		case <-ctx.Done():
			fmt.Println("[fp-worker] shutting down")
			return
		default:
		}

		raw, err := rdb.BLPop(ctx, cfg.Queue.FpJobs())
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			fmt.Printf("[fp-worker] blpop error: %v\n", err)
			continue
		}

		var job models.FpJob
		if err := json.Unmarshal([]byte(raw), &job); err != nil {
			fmt.Printf("[fp-worker] invalid job: %v\n", err)
			continue
		}

		fmt.Printf("[fp-worker] probing taskId=%s host=%s port=%d\n", job.TaskId, job.Host, job.Port)

		result := fingerprint.Probe(ctx, job.Host, job.Port)

		pocJob := models.PocJob{
			TaskId: job.TaskId,
			Target: result.URL,
			Proto:  result.Proto,
			Tags:   result.Tags,
		}

		data, _ := json.Marshal(pocJob)
		rdb.Push(ctx, cfg.Queue.PocJobs(), string(data))

		rdb.HIncrBy(ctx, cfg.Queue.StatusKey(job.TaskId), "fp_done", 1)
		fmt.Printf("[fp-worker] done host=%s:%d → target=%s tags=%v\n",
			job.Host, job.Port, result.URL, result.Tags)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Stage-4 POC-Worker：nuclei 漏洞扫描（按 tags 动态过滤模板）
// ─────────────────────────────────────────────────────────────────────────────

func runPocWorker(ctx context.Context, cfg *config.Config) {
	rdb := queue.NewClient(cfg.Redis)

	hostname, _ := os.Hostname()
	fmt.Printf("[poc-worker] started on %s, redis=%s poc=%s\n",
		hostname, cfg.Redis.Addr, cfg.Scan.PocDir)
	fmt.Printf("[poc-worker] waiting for jobs on %s ...\n", cfg.Queue.PocJobs())

	for {
		select {
		case <-ctx.Done():
			fmt.Println("[poc-worker] shutting down")
			return
		default:
		}

		raw, err := rdb.BLPop(ctx, cfg.Queue.PocJobs())
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			fmt.Printf("[poc-worker] blpop error: %v\n", err)
			continue
		}

		var job models.PocJob
		if err := json.Unmarshal([]byte(raw), &job); err != nil {
			fmt.Printf("[poc-worker] invalid job: %v\n", err)
			continue
		}

		fmt.Printf("[poc-worker] scanning taskId=%s target=%s tags=%v\n",
			job.TaskId, job.Target, job.Tags)

		findings, err := poc.ScanWithTags(ctx, job.Target, job.Tags, cfg.Scan.PocDir)
		if err != nil {
			fmt.Printf("[poc-worker] error target=%s: %v\n", job.Target, err)
		}

		for _, f := range findings {
			b, _ := json.Marshal(f)
			rdb.Push(ctx, cfg.Queue.ResultsKey(job.TaskId), string(b))
			fmt.Printf("[poc-worker] FINDING taskId=%s target=%s id=%s severity=%s\n",
				job.TaskId, f.Host, f.TemplateID, f.Info.SeverityHolder.Severity)
		}

		rdb.HIncrBy(ctx, cfg.Queue.StatusKey(job.TaskId), "poc_done", 1)
		rdb.HIncrBy(ctx, cfg.Queue.StatusKey(job.TaskId), "findings", int64(len(findings)))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// all：本地联调模式，同时启动所有 worker
// ─────────────────────────────────────────────────────────────────────────────

func runAll(cfg *config.Config, args []string) {
	fs := flag.NewFlagSet("all", flag.ExitOnError)
	portN := fs.Int("port-workers", 2, "port-worker 并发数")
	httpN := fs.Int("http-workers", 2, "http-worker 并发数")
	fpN := fs.Int("fp-workers", 1, "fp-worker 并发数")
	pocN := fs.Int("poc-workers", 1, "poc-worker 并发数")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "用法: dast-engine all [-port-workers N] [-http-workers N] [-fp-workers N] [-poc-workers N]")
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
				fmt.Printf("[all] starting %s #%d\n", name, idx)
				fn(ctx, cfg)
			}()
		}
	}

	start("port-worker", *portN, runPortWorker)
	start("http-worker", *httpN, runHttpWorker)
	start("fp-worker", *fpN, runFpWorker)
	start("poc-worker", *pocN, runPocWorker)

	fmt.Printf("[all] pipeline started: port×%d + http×%d + fp×%d + poc×%d\n",
		*portN, *httpN, *fpN, *pocN)
	fmt.Println("[all] press Ctrl+C to stop all workers")

	wg.Wait()
	fmt.Println("[all] all workers stopped")
}

// ─────────────────────────────────────────────────────────────────────────────
// 主入口
// ─────────────────────────────────────────────────────────────────────────────

func usage() {
	fmt.Fprintf(os.Stderr, `dast-engine — 分布式 DAST 扫描引擎

用法:
  dast-engine <subcommand> [flags]

子命令:
  dispatch     投递扫描任务（Stage-1）
               -task <id>   任务 ID（必填）
               -ips  <ips>  空格分隔的 IP 列表
               -file <path> IP 列表文件（每行一个 IP）
               -ports <r>   端口范围: top1000 / full / 80,443（默认由 DEFAULT_PORTS 控制）

  port-worker  端口扫描 Worker（Stage-2, naabu）
  http-worker  HTTP 指纹识别 Worker（Stage-3, httpx + wappalyzer）
  fp-worker    TCP/协议指纹 Worker（Stage-3b, fingerprintx）
  poc-worker   POC 漏洞扫描 Worker（Stage-4, nuclei）

  all          一键启动所有 worker（本地联调模式）
               -port-workers N   （默认 2）
               -http-workers N   （默认 2）
               -fp-workers   N   （默认 1）
               -poc-workers  N   （默认 1）

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

	// 全局唯一一次配置加载，所有子命令共享同一份配置
	cfg := config.Load()

	subCmd := os.Args[1]
	rest := os.Args[2:]

	switch subCmd {
	case "dispatch":
		runDispatcher(cfg, rest)

	case "port-worker":
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		runPortWorker(ctx, cfg)

	case "http-worker":
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		runHttpWorker(ctx, cfg)

	case "fp-worker":
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		runFpWorker(ctx, cfg)

	case "poc-worker":
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		runPocWorker(ctx, cfg)

	case "all":
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
