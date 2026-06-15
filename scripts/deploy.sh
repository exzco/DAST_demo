#!/bin/bash
# deploy.sh - SSH 批量部署分布式扫描 Worker 到多物理节点
# 用法：./scripts/deploy.sh
# 依赖：ssh 免密登录已配置，目标节点已安装 libpcap-dev（naabu 依赖）

set -e

# ─── 配置项（修改为你的实际节点 IP）────────────────────────────────────────────
REDIS_ADDR="${REDIS_ADDR:-10.0.0.1:6379}"
POC_DIR="/opt/scanner/poc"
INSTALL_DIR="/opt/scanner"

# 节点列表（格式：角色:IP）
# port-worker 节点：出口带宽大的机器
# poc-worker  节点：内存大的机器（nuclei 每实例约 200MB）
NODES=(
  "port:10.0.0.2"
  "port:10.0.0.3"
  "poc:10.0.0.4"
)
# ────────────────────────────────────────────────────────────────────────────────

echo "=== [deploy] Building Linux amd64 binaries ==="
make build-all

echo ""
echo "=== [deploy] Syncing poc templates from dast-engine ==="
# poc 目录从 dast-engine 同步（也可改为独立挂载 NFS）
for node_def in "${NODES[@]}"; do
  IP="${node_def#*:}"
  echo "  → syncing poc/ to root@${IP}:${POC_DIR}"
  ssh root@"${IP}" "mkdir -p ${INSTALL_DIR}/bin ${POC_DIR}"
  rsync -az --progress \
    ../engines/dast-engine/poc/ \
    root@"${IP}":"${POC_DIR}"/
done

echo ""
echo "=== [deploy] Deploying binaries and starting workers ==="

for node_def in "${NODES[@]}"; do
  ROLE="${node_def%%:*}"
  IP="${node_def#*:}"

  echo ""
  echo "  ─── Node ${IP} (role: ${ROLE}) ───"

  # 同步二进制
  rsync -az ./bin/ root@"${IP}":"${INSTALL_DIR}/bin/"

  # 停止旧进程
  ssh root@"${IP}" "pkill -f port-worker 2>/dev/null; pkill -f fp-worker 2>/dev/null; pkill -f poc-worker 2>/dev/null; sleep 1; true"

  # 按角色启动 Worker
  case "$ROLE" in
    port)
      echo "  Starting: 2x port-worker + 1x fp-worker"
      ssh root@"${IP}" "
        export REDIS_ADDR=${REDIS_ADDR}
        export POC_DIR=${POC_DIR}
        nohup ${INSTALL_DIR}/bin/port-worker >> /var/log/port-worker.log 2>&1 &
        nohup ${INSTALL_DIR}/bin/port-worker >> /var/log/port-worker.log 2>&1 &
        nohup ${INSTALL_DIR}/bin/fp-worker   >> /var/log/fp-worker.log   2>&1 &
        echo 'Workers started on ${IP}'
      "
      ;;
    poc)
      echo "  Starting: 2x poc-worker + 1x fp-worker"
      ssh root@"${IP}" "
        export REDIS_ADDR=${REDIS_ADDR}
        export POC_DIR=${POC_DIR}
        nohup ${INSTALL_DIR}/bin/poc-worker >> /var/log/poc-worker.log 2>&1 &
        nohup ${INSTALL_DIR}/bin/poc-worker >> /var/log/poc-worker.log 2>&1 &
        nohup ${INSTALL_DIR}/bin/fp-worker  >> /var/log/fp-worker.log  2>&1 &
        echo 'POC Workers started on ${IP}'
      "
      ;;
  esac
done

echo ""
echo "=== [deploy] All nodes deployed! ==="
echo ""
echo "  验证各节点进程："
for node_def in "${NODES[@]}"; do
  IP="${node_def#*:}"
  echo "  ssh root@${IP} 'pgrep -fa worker'"
done
echo ""
echo "  发起扫描任务（从调度节点执行）："
echo "  REDIS_ADDR=${REDIS_ADDR} ./bin/dispatcher -task t001 -file targets.txt -ports top1000"
echo ""
echo "  查看进度："
echo "  make status TASK=t001 REDIS=${REDIS_ADDR}"
