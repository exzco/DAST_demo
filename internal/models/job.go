//	Dispatcher → PortWorker → HttpWorker → PocWorker
//
// 各阶段通过 Redis List 传递数据：
//
//	scan:port:jobs  → PortJob
//	scan:http:jobs  → HttpJob
//	scan:poc:jobs   → PocJob
package models

type PortJob struct {
	TaskId string `json:"taskId"`
	IP     string `json:"ip"`
	Ports  string `json:"ports"` // "top1000" / "1-65535" / "80,443,8080"
}

type FpJob struct {
	TaskId     string `json:"taskId"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Retry      int    `json:"retry"`
	FailReason string `json:"failReason,omitempty"`
}

type PocJob struct {
	TaskId     string   `json:"taskId"`
	Target     string   `json:"target"`
	Proto      string   `json:"proto"`
	Tags       []string `json:"tags"`
	Retry      int      `json:"retry"`
	FailReason string   `json:"failReason,omitempty"`
}
