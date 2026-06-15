// Package models 定义分布式扫描各阶段的任务结构体
//
// 流水线（3 阶段，输入均为 IP）：
//
//	Dispatcher → PortWorker → HttpWorker → PocWorker
//	              (naabu)      (httpx)      (nuclei)
//
// 各阶段通过 Redis List 传递数据：
//
//	scan:port:jobs  → PortJob
//	scan:http:jobs  → HttpJob
//	scan:poc:jobs   → PocJob（携带 tech tags）
package models

// PortJob Dispatcher 直接推入 scan:port:jobs 队列
// PortWorker 消费：对单个 IP 做 TCP 端口扫描
type PortJob struct {
	TaskId string `json:"taskId"`
	IP     string `json:"ip"`    // 扫描目标 IP
	Ports  string `json:"ports"` // "top1000" / "1-65535" / "80,443,8080"
}

// HttpJob PortWorker 推入 scan:http:jobs 队列
// HttpWorker 消费：httpx 探测 HTTP/HTTPS，识别技术栈（wappalyzer）
type HttpJob struct {
	TaskId string `json:"taskId"`
	Host   string `json:"host"` // IP 地址
	Port   int    `json:"port"` // 开放端口号
}
type FpJob struct {
	TaskId string `json:"taskId"`
	Host string `json:"host"`
	Port int `json:"port"`	
}
// PocJob HttpWorker 推入 scan:poc:jobs 队列（携带 tech tags）
// PocWorker 消费：nuclei 按 Tags 动态过滤模板执行 POC
type PocJob struct {
	TaskId string   `json:"taskId"`
	Target string   `json:"target"` // http://ip:port 或 https://ip:port 或 ip:port（TCP 服务）
	Proto  string   `json:"proto"`  // "http" / "https" / "tcp"
	Tags   []string `json:"tags"`   // httpx wappalyzer 识别的技术栈，如 ["wordpress","php","nginx"]
}
