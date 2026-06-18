**流水线：IP → 端口（Nmap） → 服务指纹（Nmap -sV） → 漏洞验证（Nuclei v3）**

### 1. 安装 Go 环境
*   **版本要求**：Go >= 1.24.0

### 2. 安装 Nmap 二进制文件
端口扫描与指纹识别依赖底层 Nmap 驱动，扫描节点所在的机器须安装 Nmap 并将其加入环境变量：
*   **Ubuntu / Debian / WSL**：
    
    ```bash
    sudo apt update && sudo apt install -y nmap
    ```
*   **macOS**：
    
    ```bash
    brew install nmap
    ```
*   **Windows**：
    安装官方自安装包或使用包管理器：
    ```powershell
    scoop install nmap
    ```

### 3. 获取 Nuclei POC 漏洞模板
Nuclei 引擎运行需要本地 YAML 格式的 POC 模板。请在项目根目录下通过 Git 快速克隆官方模板库到 `./poc`：
```bash
git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git ./poc
```

---

## 项目结构

```
DAST_demo/
├── .env                    
├── main.go                 
├── go.mod                   
├── README.md               
├── data/                    
├── result/
│   └── result.json         
├── internal/
│   ├── config/              
│   ├── models/              
│   ├── queue/               
│   ├── portscan/           
│   ├── fingerprint/         
│   └── poc/                 
```

---

## 快速开始（本地联调）

**本机启动 Redis**
```bash
docker run -d --name dast-redis -p 6379:6379 redis:7-alpine
```

### 2. 编译项目
```bash
go build -o scan main.go
```

### 3. 启动所有 Worker 
```bash
./scan worker
```

### 4. 另起终端，投递扫描任务
```bash
./scan dispatch -task t002 -ips "127.0.0.1 127.0.0.1:8088" -ports "top1000"
```

### 5. 查看结果
执行过程和漏洞发现结果会写入到 `result/result.json` 中。也可以直接查询 Redis。

---

## 多节点部署

只需要在各个节点上分工启动对应的子服务，并指向同一个中心 Redis 地址即可：

```bash
# 1. 端口扫描节点
REDIS_ADDR=10.0.0.1:6379 ./scan.exe port-worker

# 2. 指纹与协议识别节点
REDIS_ADDR=10.0.0.1:6379 ./scan.exe fp-worker

# 3. POC 漏洞验证节点
REDIS_ADDR=10.0.0.1:6379 ./scan.exe poc-worker
```

---

## Redis 数据流与队列机制

| 队列 / 键名 | 数据类型 | 推送节点 | 消费/监听节点 | 功能说明 |
| :--- | :--- | :--- | :--- | :--- |
| `scan:port:jobs` | **List** | Dispatcher | PortWorker | 端口扫描任务队列（IP、扫描端口范围） |
| `scan:fp:jobs` | **List** | PortWorker | FpWorker | 统一协议与指纹识别队列（IP、端口） |
| `scan:poc:jobs` | **List** | FpWorker | PocWorker | 漏洞验证队列（携带识别到的技术栈 tags） |
| `scan:results:{taskId}` | **List** | PocWorker | - | 存储任务 `{taskId}` 发现的漏洞详情 (JSON) |
| `scan:status:{taskId}` | **Hash** | 共享更新 | - | 记录任务运行状态计数器（已扫 IP、开放端口、指纹/POC完成数） |
| `scan:control` | **Pub/Sub** | 控制端/用户 | 共享监听 | 广播任务中止信号，Worker 接收后内存记录并丢弃该任务的后续 Job 

---

## 常用 Redis 查询与管理命令

在调试与运行期间，可以使用 `redis-cli` 工具执行以下命令监控系统运行状态：

### 1. 查询各阶段队列积压长度
```bash
# 1. 查询待扫描的端口任务积压长度
redis-cli LLEN scan:port:jobs

# 2. 查询待识别指纹的任务积压长度
redis-cli LLEN scan:fp:jobs

# 3. 查询待漏洞验证的任务积压长度
redis-cli LLEN scan:poc:jobs

# 4. 查看最新被扫描发现并推送到 Redis 的结果
redis-cli LRANGE scan:results:t002 0 -1

# 5. 查看任务进度仪表盘
redis-cli HGETALL scan:status:t002

# 6. 中止指定任务
redis-cli PUBLISH scan:control "t002"

# 7. 清理队列垃圾缓存
redis-cli DEL scan:port:jobs scan:fp:jobs scan:poc:jobs
```
