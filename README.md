# 分布式 DAST 扫描引擎

**流水线：IP → 端口 → 指纹 → POC，性能与节点数量呈线性关系**

---

## 项目结构

```
DAST-Engine/
├── cmd/
│   ├── dispatcher/main.go   # 任务分发：IP 列表 → scan:port:jobs 队列
│   ├── port-worker/main.go  # Stage-1：naabu 端口扫描（可水平扩展）
│   ├── fp-worker/main.go    # Stage-2：协议识别 + 指纹匹配
│   └── poc-worker/main.go   # Stage-3：按指纹 tags 动态执行 nuclei POC
├── internal/
│   ├── models/job.go        # PortJob / FpJob / PocJob 数据结构
│   ├── queue/redis.go       # Redis BLPop/RPush 封装
│   ├── portscan/naabu.go    # 单 IP 端口扫描
│   ├── fingerprint/
│   │   ├── rules.go         # HTTP + Banner 特征规则表
│   │   ├── http.go          # HTTP Header/Body 指纹识别
│   │   └── banner.go        # TCP Banner 识别 + 统一入口 Probe()
│   └── poc/nuclei.go        # 按 tags 动态过滤 nuclei 模板
├── poc -> ../engines/dast-engine/poc   # 软链复用模板
├── go.mod
├── Makefile
└── scripts/deploy.sh        # SSH 批量部署
```

---

## 快速开始（本地联调）

**前提：本机启动 Redis**
```bash
docker run -d -p 6379:6379 redis:7-alpine
```

**创建 poc 软链（复用现有模板）**
```bash
ln -s ../engines/dast-engine/poc ./poc
```

**编译 & 启动全部 Worker**
```bash
make dev-all
```

**投递扫描任务**
```bash
make dispatch TASK=t001 IPS=192.168.1.1,192.168.1.2 PORTS=top1000
# 或扫描文件列表
REDIS_ADDR=127.0.0.1:6379 ./bin/dispatcher -task t001 -file targets.txt
```

**查看进度和结果**
```bash
make status  TASK=t001   # 查看各阶段计数
make results TASK=t001   # 查看漏洞发现
make queue-len           # 查看各阶段队列积压
```

---

## 多物理节点部署

**修改 scripts/deploy.sh 中的节点配置：**
```bash
REDIS_ADDR="10.0.0.1:6379"   # 中心 Redis 地址
NODES=(
  "port:10.0.0.2"  # 端口扫描节点（带宽大）
  "port:10.0.0.3"  # 端口扫描节点
  "poc:10.0.0.4"   # POC 扫描节点（内存大）
)
```

**一键部署：**
```bash
chmod +x scripts/deploy.sh
./scripts/deploy.sh
```

---

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `REDIS_ADDR` | `127.0.0.1:6379` | 中心 Redis 地址（所有节点相同） |
| `POC_DIR` | `./poc` | nuclei 模板目录路径 |

---

## Redis 数据流

```
scan:port:jobs  List  Dispatcher 推入 → PortWorker BLPop 消费
scan:fp:jobs    List  PortWorker 推入 → FpWorker   BLPop 消费
scan:poc:jobs   List  FpWorker   推入 → PocWorker  BLPop 消费
scan:results:{taskId}  List   漏洞结果（PocWorker 写入）
scan:status:{taskId}   Hash   进度统计（各 Worker 更新）
```

---

## 线性扩展说明

```
N 个 PortWorker 竞争 scan:port:jobs：
  1 Worker  → T   时间
  2 Workers → T/2 时间  (2倍速)
  4 Workers → T/4 时间  (4倍速)
```

BLPop 的原子性保证每个 IP 任务只被一个 Worker 处理，无需手动分片。




查看任务详情
redis-cli hgetall scan:status:taskID 
```bash
redis-cli hgetall scan:status:t001
1) "status"
2) "running"
3) "total_ips"
4) "1"
5) "ports"
6) "full"
7) "started_at"
8) "2026-06-15T11:45:22+08:00"
```

查看队列待扫描的 port-jobs
redis-cli lrange scan:port:jobs 0 -1
```bash
redis-cli lrange scan:port:jobs 0 -1
1) "{\"taskId\":\"t001\",\"ip\":\"172.28.0.15\",\"ports\":\"full\"}"
```

查看扫描结果 
redis-cli lrange scan:results:t001 0 -1


查看 redis 当前所有 key 
redis-cli keys "*"
