// Package fingerprint HTTP 协议层指纹识别
// 通过 HTTP Response Header + Body 特征匹配技术栈标签
package fingerprint

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ProbeResult HTTP 指纹识别结果
type ProbeResult struct {
	URL   string   // 最终可访问的 URL（http:// 或 https://）
	Proto string   // "http" / "https" / "tcp"（无 HTTP 响应）
	Tags  []string // 识别出的指纹标签
}

// httpClient 全局共用的 HTTP 客户端（跳过 TLS 验证，适配自签证书内网环境）
var httpClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout: 3 * time.Second,
		}).DialContext,
	},
	Timeout: 6 * time.Second,
	// 不跟随重定向，避免干扰指纹识别
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// ProbeHTTP 对 host:port 做 HTTP/HTTPS 探测并识别指纹
// 优先尝试明文 HTTP，失败则尝试 HTTPS，最后回退 TCP
func ProbeHTTP(ctx context.Context, host string, port int) ProbeResult {
	hostPort := fmt.Sprintf("%s:%d", host, port)

	// 1. 尝试明文 HTTP
	if url, headers, body, ok := doHTTPGet(ctx, "http://"+hostPort); ok {
		tags := matchHTTPTags(headers, body)
		return ProbeResult{URL: url, Proto: "http", Tags: tags}
	}

	// 2. 尝试 HTTPS
	if url, headers, body, ok := doHTTPGet(ctx, "https://"+hostPort); ok {
		tags := matchHTTPTags(headers, body)
		return ProbeResult{URL: url, Proto: "https", Tags: tags}
	}

	// 3. 无 HTTP 响应，标记为 TCP（交给 banner.go 处理）
	return ProbeResult{URL: hostPort, Proto: "tcp", Tags: nil}
}

// doHTTPGet 对 url 发送 GET 请求，返回最终 URL、Header 字符串、Body 字符串
func doHTTPGet(ctx context.Context, url string) (finalURL, headers, body string, ok bool) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", "", "", false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; scanner/1.0)")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", "", "", false
	}
	defer resp.Body.Close()

	// 最多读取 64KB Body 用于特征匹配（避免超大页面耗尽内存）
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))

	// 将所有 Header 序列化为一个字符串便于规则匹配
	var sb strings.Builder
	for k, vals := range resp.Header {
		for _, v := range vals {
			sb.WriteString(k)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteString("\n")
		}
	}

	return resp.Request.URL.String(), sb.String(), string(bodyBytes), true
}

// matchHTTPTags 遍历 HTTPRules，收集所有命中的 tags
// 同一目标可能匹配多条规则（如 Tomcat + Java）
func matchHTTPTags(headers, body string) []string {
	tagSet := make(map[string]bool)
	for _, rule := range HTTPRules {
		if rule.Match(headers, body) {
			for _, tag := range rule.Tags {
				tagSet[tag] = true
			}
		}
	}

	if len(tagSet) == 0 {
		return FallbackTags
	}

	tags := make([]string, 0, len(tagSet))
	for t := range tagSet {
		tags = append(tags, t)
	}
	return tags
}
