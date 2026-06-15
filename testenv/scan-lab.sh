#!/usr/bin/env bash
# ============================================================
#  DAST-Engine 靶场一键测试脚本
#  用法: ./scan-lab.sh [start|stop|scan|status|results|clean]
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE_DIR="$(dirname "$SCRIPT_DIR")"
TESTENV_DIR="$SCRIPT_DIR"

REDIS_ADDR="${REDIS_ADDR:-127.0.0.1:6379}"
TASK_ID="lab-$(date +%s)"

# 靶场目标 IP 列表（对应 docker-compose 中分配的静态 IP）
LAB_TARGETS="172.28.0.10,172.28.0.11,172.28.0.12,172.28.0.13,172.28.0.14,172.28.0.15,172.28.0.16,172.28.0.20,172.28.0.21,172.28.0.22,172.28.0.23,172.28.0.30,172.28.0.31"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERR]${NC}   $*"; }

# ─── 启动靶场 ─────────────────────────────────────────────────
start() {
    info "启动靶场环境..."
    cd "$TESTENV_DIR"
    docker compose up -d --remove-orphans
    sleep 240



    echo "║ Nginx 1.14       ║ :8080         ║ HTTP/2 漏洞, stub_status暴露 "
    echo "║ Apache 2.4.49    ║ :8081         ║ CVE-2021-41773 路径穿越 "
    echo "║ Tomcat 9.0.30    ║ :8082 :8009   ║ CVE-2020-1938 Ghostcat  "
    echo "║ WebLogic 12c     ║ :7001 :7002   ║ 反序列化 RCE            "
    echo "║ Jenkins 2.235    ║ :8083         ║ Script Security bypass  "
    echo "║ WordPress 5.0    ║ :8084         ║ 多个 XSS/RCE            "
    echo "║ phpMyAdmin 4.8   ║ :8085         ║ CVE-2018-12613 文件包含 "
    echo "║ MySQL 5.7        ║ :3306         ║ 远程 root 无密码限制       "
    echo "║ Redis 4.0 (未授权)║ :6380         ║ CVE-2022-0543            "
    echo "║ MongoDB 4.2      ║ :27017        ║ 无认证开放                "
    echo "║ Elasticsearch 7.6║ :9200 :9300   ║ 无认证信息泄露            "
    echo "║ Grafana 8.3      ║ :3000         ║ CVE-2021-43798 文件读取  "
    echo "║ Kibana 7.6       ║ :5601         ║ 无认证访问               "

    ok "靶机 IP 段: 172.28.0.10-31"
}

# ─── 停止靶场 ─────────────────────────────────────────────────
stop() {
    info "停止靶场..."
    cd "$TESTENV_DIR"
    docker compose down
    ok "靶场已停止"
}

# ─── 构建扫描器 ───────────────────────────────────────────────
build() {
    info "编译扫描器 (darwin/arm64)..."
    cd "$ENGINE_DIR"
    GOOS=darwin GOARCH=arm64 make build-all 2>&1 || {
        warn "arm64 编译失败，尝试 amd64..."
        GOOS=darwin GOARCH=amd64 make build-all
    }
    ok "编译完成"
}

# ─── 启动流水线 Workers ───────────────────────────────────────
start_workers() {
    info "启动 Pipeline Workers..."
    cd "$ENGINE_DIR"

    REDIS_ADDR=$REDIS_ADDR ./bin/port-worker &
    PORT_WORKER_PID=$!
    REDIS_ADDR=$REDIS_ADDR ./bin/port-worker &
    PORT_WORKER_PID2=$!
    REDIS_ADDR=$REDIS_ADDR ./bin/http-worker &
    HTTP_WORKER_PID=$!
    REDIS_ADDR=$REDIS_ADDR ./bin/http-worker &
    HTTP_WORKER_PID2=$!
    REDIS_ADDR=$REDIS_ADDR ./bin/poc-worker &
    POC_WORKER_PID=$!

    # 保存 PID 方便后续 kill
    echo "$PORT_WORKER_PID $PORT_WORKER_PID2 $HTTP_WORKER_PID $HTTP_WORKER_PID2 $POC_WORKER_PID" > /tmp/dast-pids

    ok "Workers 已启动 (PIDs: $(cat /tmp/dast-pids))"
    sleep 2
}

# ─── 停止 Workers ─────────────────────────────────────────────
stop_workers() {
    if [ -f /tmp/dast-pids ]; then
        info "停止 Workers..."
        kill $(cat /tmp/dast-pids) 2>/dev/null || true
        rm -f /tmp/dast-pids
    fi
    pkill -f port-worker 2>/dev/null || true
    pkill -f http-worker 2>/dev/null || true
    pkill -f poc-worker  2>/dev/null || true
    ok "Workers 已停止"
}

# ─── 投递扫描任务 ─────────────────────────────────────────────
dispatch() {
    local task_id="${1:-$TASK_ID}"
    local targets="${2:-$LAB_TARGETS}"
    local ports="${3:-80,443,8080,8081,8082,8083,8084,8085,7001,7002,3000,5601,6379,6380,3306,27017,9200,9300,8009}"

    info "投递扫描任务..."
    info "  Task ID : $task_id"
    info "  Targets : $targets"
    info "  Ports   : $ports"
    echo ""

    cd "$ENGINE_DIR"
    REDIS_ADDR=$REDIS_ADDR ./bin/dispatcher \
        -task  "$task_id" \
        -ips   "$targets" \
        -ports "$ports"

    echo ""
    info "查看进度: TASK=$task_id"
    echo "  make status  TASK=$task_id"
    echo "  make results TASK=$task_id"
    echo "  ./scan-lab.sh status $task_id"
}

# ─── 查看任务进度 ─────────────────────────────────────────────
show_status() {
    local task_id="${1:-}"
    if [ -z "$task_id" ]; then
        # 显示所有任务
        info "所有扫描任务:"
        redis-cli -h 127.0.0.1 -p 6379 keys "scan:status:*" | while read key; do
            echo ""
            echo "  [$key]"
            redis-cli -h 127.0.0.1 -p 6379 hgetall "$key" | paste - - | sed 's/^/    /'
        done
    else
        info "任务 [$task_id] 进度:"
        redis-cli -h 127.0.0.1 -p 6379 hgetall "scan:status:$task_id"
        echo ""
        info "队列积压:"
        echo "  port jobs : $(redis-cli -h 127.0.0.1 -p 6379 llen scan:port:jobs)"
        echo "  http jobs : $(redis-cli -h 127.0.0.1 -p 6379 llen scan:http:jobs)"
        echo "  poc  jobs : $(redis-cli -h 127.0.0.1 -p 6379 llen scan:poc:jobs)"
    fi
}

# ─── 查看扫描结果 ─────────────────────────────────────────────
show_results() {
    local task_id="${1:-}"
    if [ -z "$task_id" ]; then
        err "用法: $0 results <task-id>"
        exit 1
    fi

    local count
    count=$(redis-cli -h 127.0.0.1 -p 6379 llen "scan:results:$task_id")
    info "任务 [$task_id] 发现漏洞: $count 条"
    echo ""

    if [ "$count" -eq 0 ]; then
        warn "暂无结果（可能仍在扫描中）"
        return
    fi

    echo "════════════════════════════════════════════════════════"
    redis-cli -h 127.0.0.1 -p 6379 lrange "scan:results:$task_id" 0 -1 | \
        python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        obj = json.loads(line)
        sev = obj.get('severity','?').upper()
        colors = {'CRITICAL':'\033[0;31m','HIGH':'\033[0;31m','MEDIUM':'\033[1;33m','LOW':'\033[0;34m'}
        c = colors.get(sev,'\033[0m')
        nc = '\033[0m'
        print(f\"{c}[{sev:8s}]{nc} {obj.get('template-id','?'):40s} {obj.get('host','?')}\")
        if obj.get('matched-at'):
            print(f'         → {obj[\"matched-at\"]}')
    except:
        print(line)
" 2>/dev/null || redis-cli -h 127.0.0.1 -p 6379 lrange "scan:results:$task_id" 0 -1
    echo "════════════════════════════════════════════════════════"
}

# ─── 一键全流程扫描 ───────────────────────────────────────────
scan() {
    local task_id="lab-$(date +%s)"

    echo ""
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║         🚀  DAST-Engine 靶场全流程扫描                   ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""

    # 1. 编译
    build

    # 2. 启动 Workers
    start_workers

    # 3. 投递任务
    dispatch "$task_id"

    echo ""
    info "扫描进行中，等待 60 秒后查看结果..."
    echo "  实时状态: watch -n3 './scan-lab.sh status $task_id'"
    echo "  结果查看: ./scan-lab.sh results $task_id"
    echo ""
    echo "Task ID: $task_id"
}

# ─── 清理 Redis 数据 ──────────────────────────────────────────
clean_redis() {
    info "清理 Redis 扫描数据..."
    redis-cli -h 127.0.0.1 -p 6379 keys "scan:*" | xargs -r redis-cli -h 127.0.0.1 -p 6379 del
    ok "Redis 数据已清理"
}

# ─── 帮助 ─────────────────────────────────────────────────────
usage() {
    echo ""
    echo "用法: $0 <命令> [参数]"
    echo ""
    echo "  start              启动靶场 Docker 环境"
    echo "  stop               停止靶场 Docker 环境"
    echo "  build              编译扫描器二进制"
    echo "  workers-start      启动 Pipeline Workers"
    echo "  workers-stop       停止 Pipeline Workers"
    echo "  dispatch [taskid] [ips] [ports]  投递扫描任务"
    echo "  scan               一键全流程（编译→启动Workers→投递任务）"
    echo "  status [taskid]    查看任务进度"
    echo "  results <taskid>   查看漏洞结果"
    echo "  clean              清理 Redis 扫描数据"
    echo ""
    echo "快速开始:"
    echo "  $0 start           # 先启动靶场"
    echo "  $0 scan            # 再启动扫描器扫描"
    echo "  $0 status          # 查看所有任务进度"
    echo ""
}

# ─── 主入口 ───────────────────────────────────────────────────
case "${1:-help}" in
    start)         start ;;
    stop)          stop ;;
    build)         build ;;
    workers-start) start_workers ;;
    workers-stop)  stop_workers ;;
    dispatch)      dispatch "${2:-}" "${3:-}" "${4:-}" ;;
    scan)          scan ;;
    status)        show_status "${2:-}" ;;
    results)       show_results "${2:-}" ;;
    clean)         clean_redis ;;
    *)             usage ;;
esac
