// Package portscan 封装 naabu SDK，对单个 IP 进行端口扫描
// 每个 PortWorker 独立调用此函数，多 Worker 并发扫描不同 IP
package portscan

import (
	"context"
	"fmt"
	"strings"

	"distributed-scanner/internal/config"
	log "distributed-scanner/log"

	naaburesult "github.com/projectdiscovery/naabu/v2/pkg/result"
	naaburunner "github.com/projectdiscovery/naabu/v2/pkg/runner"
)

// ScanIP 对单个 IP 做端口扫描，返回开放的端口号列表。
func ScanIP(ctx context.Context, ip string, portRange string, scanCfg config.PortScanConfig) ([]int, error) {
	log.Printf("[portscan] scanning ip=%s ports=%s rate=%d threads=%d\n",
		ip, portRange, scanCfg.Rate, scanCfg.Threads)

	var openPorts []int

	options := &naaburunner.Options{
		Rate:    scanCfg.Rate,
		Timeout: scanCfg.Timeout,
		Threads: scanCfg.Threads,

		Silent: true, // 不往 stdout 打冗余日志
		JSON:   false,

		// 跳过主机发现，直接端口扫描
		WithHostDiscovery: false,
		SkipHostDiscovery: true,
	}

	if scanCfg.ScanType == "syn" {
		options.ScanType = "s"
	} else {
		options.ScanType = "c"
	}

	options.OnResult = func(hr *naaburesult.HostResult) {
		if hr == nil {
			return
		}
		for _, p := range hr.Ports {
			openPorts = append(openPorts, p.Port)
		}
	}


	// 根据 portRange 参数决定扫描模式
	switch portRange {
	case "top1000", "":
		options.TopPorts = "1000"
	case "full":
		options.Ports = "1-65535"
	default:
		// 允许自定义端口列表，如 "80,443,8080,8443"
		options.Ports = portRange
	}

	r, err := naaburunner.NewRunner(options)
	if err != nil {
		return nil, fmt.Errorf("[portscan] create runner failed: %w", err)
	}
	defer r.Close()

	ip = strings.TrimSpace(ip)
	if err := r.AddTarget(ip); err != nil {
		return nil, fmt.Errorf("[portscan] add target failed ip=%s: %w", ip, err)
	}

	if err := r.RunEnumeration(ctx); err != nil {
		return nil, fmt.Errorf("[portscan] enumeration failed ip=%s: %w", ip, err)
	}

	log.Printf("[portscan] ip=%s found %d open ports\n", ip, len(openPorts))
	return openPorts, nil
}
