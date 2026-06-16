# 分布式 DAST 扫描引擎

**流水线：IP → 端口 → 指纹 → POC，性能与节点数量呈线性关系**

---

## 项目结构

```
DAST_demo/
├── fingerprints.json        # 动态指纹规则存储文件，包含 HTTP 和 TCP 规则
├── main.go                  # 扫描引擎入口，管理各阶段 worker 与任务调度
├── go.mod
├── go.sum
├── README.md
├── internal/
│   ├── config/              # 运行时配置管理，由环境变量填充，支持指纹文件配置
│   ├── models/              # 定义各阶段传递的任务消息结构 (PortJob / FpJob/PocJob 等)
│   ├── queue/               # Redis 客户端封装，支持 BLPop 阻塞出队、RPush 进队及 Hash 状态自增
│   ├── portscan/            # 端口扫描模块，基于 naabu SDK，支持 Connect (非 root) 与 SYN (需要 root) 扫描
│   ├── fingerprint/         # 协议与指纹识别模块，支持加载 JSON 指纹规则，包含 HTTP 与 TCP banner 主被动探测
│   └── poc/                 # 漏洞验证模块，基于 nuclei SDK，支持线程安全引擎缓存与反射状态重置
└── testenv/                 # 容器靶场测试环境 (Docker Compose)
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

**编译扫描程序**
```bash
go build -o scan.exe main.go
```

**本地一键启动所有 Worker**
```bash
# 启动所有 Worker（包括 2个端口扫描协程、1个指纹探测协程、1个漏洞扫描协程）
REDIS_ADDR=127.0.0.1:6379 ./scan.exe all
```

**投递扫描任务**
```bash
# 通过参数指定 IP 列表与端口范围
REDIS_ADDR=127.0.0.1:6379 ./scan.exe dispatch -task t001 -ips "192.168.1.1 192.168.1.2" -ports top1000

# 或扫描文件列表中的目标 IP
REDIS_ADDR=127.0.0.1:6379 ./scan.exe dispatch -task t001 -file targets.txt
```

**查看进度和结果**
> 提示：已全部整合为 Redis 直连查询，详情请参见下方 **[常用 Redis 查询与管理命令](#常用-redis-查询与管理命令)**。

---

## 多物理节点分布式部署

在分布式架构中，您只需要在各个节点上分工启动对应的子服务，并指向同一个中心 Redis 地址即可：

```bash
# 1. 端口扫描节点 (带宽敏感，可部署多台)
REDIS_ADDR=10.0.0.1:6379 ./scan.exe port-worker

# 2. 指纹与协议识别节点 (CPU/网络敏感，可部署多台)
REDIS_ADDR=10.0.0.1:6379 ./scan.exe fp-worker

# 3. POC 漏洞验证节点 (IO/内存敏感，可部署多台)
REDIS_ADDR=10.0.0.1:6379 ./scan.exe poc-worker
```

---

## Redis 数据流与队列机制

本引擎的分布式解耦、任务分发与实时控制完全基于 Redis 队列与订阅通道：

| 队列 / 键名 | 数据类型 | 推送节点 | 消费/监听节点 | 功能说明 |
| :--- | :--- | :--- | :--- | :--- |
| `scan:port:jobs` | **List** | Dispatcher | PortWorker | 端口扫描任务队列（IP、扫描端口范围） |
| `scan:fp:jobs` | **List** | PortWorker | FpWorker | 统一协议与指纹识别队列（IP、端口） |
| `scan:poc:jobs` | **List** | FpWorker | PocWorker | 漏洞验证队列（携带识别到的技术栈 tags） |
| `scan:results:{taskId}` | **List** | PocWorker | - | 存储任务 `{taskId}` 发现的漏洞详情 (JSON) |
| `scan:status:{taskId}` | **Hash** | 共享更新 | - | 记录任务运行状态计数器（已扫 IP、开放端口、指纹/POC完成数） |
| `scan:control` | **Pub/Sub** | 控制端/用户 | 共享监听 | 广播任务中止信号，Worker 接收后内存记录并丢弃该任务的后续 Job |

---

## 常用 Redis 查询与管理命令

在调试与运行期间，可以使用 `redis-cli` 工具执行以下命令监控系统运行状态：

### 1. 查询各阶段队列积压长度
```bash
# 查询待扫描的端口任务数
redis-cli LLEN scan:port:jobs

# 查询待识别指纹的任务数
redis-cli LLEN scan:fp:jobs

# 查询待漏洞验证的任务数
redis-cli LLEN scan:poc:jobs
```

### 2. 查看队列中待处理的任务内容
```bash
# 查看端口扫描队列前 5 个任务
redis-cli LRANGE scan:port:jobs 0 4
```

### 3. 查看扫描任务进度及元数据
```bash
# 查看任务 t001 的实时状态与计数器面板
redis-cli HGETALL scan:status:t001
```

### 4. 实时下发任务中止指令
```bash
# 中止任务 t001（Worker 将直接抛弃该任务的后续所有出队 Job）
redis-cli PUBLISH scan:control "t001"
```

### 5. 查看发现的漏洞结果
```bash
# 查看任务 t001 所有被验证的漏洞
redis-cli LRANGE scan:results:t001 0 -1
```

### 6. 清理残留任务队列
```bash
# 删除积压任务
redis-cli DEL scan:port:jobs scan:fp:jobs scan:poc:jobs
```

---

## 线性扩展说明

```
N 个 PortWorker 竞争 scan:port:jobs：
  1 Worker  → T   时间
  2 Workers → T/2 时间  (2倍速)
  4 Workers → T/4 时间  (4倍速)
```
