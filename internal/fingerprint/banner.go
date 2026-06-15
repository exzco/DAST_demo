// Package fingerprint TCP Banner 指纹识别
// 对非 HTTP 协议的开放端口，直接读取 TCP 原始应答数据做特征匹配
package fingerprint

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// ProbeBanner 对 host:port 发送探测字节并读取 Banner
// 用于识别 Redis / MySQL / MongoDB / SSH 等非 HTTP 服务
func ProbeBanner(ctx context.Context, host string, port int) []string {
	hostPort := fmt.Sprintf("%s:%d", host, port)

	dialer := &net.Dialer{}
	connCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(connCtx, "tcp", hostPort)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		conn.Write([]byte("PING\r\n"))
		conn.SetDeadline(time.Now().Add(1 * time.Second))
		n, err = conn.Read(buf)
		if err != nil || n == 0 {
			return nil
		}
	}

	banner := string(buf[:n])
	return matchBannerTags(banner)
}

// matchBannerTags 遍历 BannerRules，用前缀匹配识别服务类型
func matchBannerTags(banner string) []string {
	tagSet := make(map[string]bool)
	for _, rule := range BannerRules {
		if strings.HasPrefix(banner, rule.Prefix) {
			for _, tag := range rule.Tags {
				tagSet[tag] = true
			}
		}
	}
	tags := make([]string, 0, len(tagSet))
	for t := range tagSet {
		tags = append(tags, t)
	}
	return tags
}

// Probe 完整指纹探测入口：先 HTTP，失败则 Banner
// FpWorker 调用此函数，返回最终目标 URL 和识别出的标签
func Probe(ctx context.Context, host string, port int) ProbeResult {
	// 先尝试 HTTP/HTTPS 协议识别
	result := ProbeHTTP(ctx, host, port)

	if result.Proto == "tcp" {
		// HTTP 失败：尝试 TCP Banner 识别
		bannerTags := ProbeBanner(ctx, host, port)
		if len(bannerTags) > 0 {
			result.Tags = bannerTags
		} else {
			// 仍无法识别：使用兜底标签
			result.Tags = FallbackTags
		}
	}

	fmt.Printf("[fingerprint] %s:%d → proto=%s tags=%v\n", host, port, result.Proto, result.Tags)
	return result
}
