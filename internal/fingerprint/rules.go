// Package fingerprint 定义指纹识别规则
// 将 HTTP Response 特征和 TCP Banner 特征映射为 nuclei 模板 tags
package fingerprint

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// HTTPRule HTTP 响应特征匹配规则
type HTTPRule struct {
	Tags  []string
	Match func(headers, body string) bool
}

// BannerRule TCP Banner 特征匹配规则（非 HTTP 端口）
type BannerRule struct {
	Tags   []string
	Prefix string // Banner 前缀匹配（字节前缀）
}

// FallbackTags 无法识别指纹时的兜底标签，运行通用配置错误检测
var FallbackTags = []string{"exposure", "misconfig", "config"}

// HTTPRules 从 HTTP Response Header + Body 识别技术栈
var HTTPRules []HTTPRule

// BannerRules TCP 原始 Banner 特征匹配（非 HTTP 协议端口）
var BannerRules []BannerRule

// JSONRules structures the JSON file content
type JSONRules struct {
	HTTPRules   []HTTPRuleJSON   `json:"http_rules"`
	BannerRules []BannerRuleJSON `json:"banner_rules"`
}

type HTTPRuleJSON struct {
	Tags    []string `json:"tags"`
	Headers []string `json:"headers"`
	Body    []string `json:"body"`
}

type BannerRuleJSON struct {
	Tags      []string `json:"tags"`
	Prefix    string   `json:"prefix,omitempty"`
	HexPrefix string   `json:"hex_prefix,omitempty"`
}

// LoadRules 从 JSON 文件加载 HTTP 和 TCP Banner 指纹规则
func LoadRules(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read rules file failed: %w", err)
	}

	var jsonRules JSONRules
	if err := json.Unmarshal(data, &jsonRules); err != nil {
		return fmt.Errorf("parse rules json failed: %w", err)
	}

	// 加载 HTTP 规则
	var httpRules []HTTPRule
	for _, rule := range jsonRules.HTTPRules {
		headersList := rule.Headers
		bodyList := rule.Body
		
		httpRules = append(httpRules, HTTPRule{
			Tags: rule.Tags,
			Match: func(headers, body string) bool {
				for _, h := range headersList {
					if strings.Contains(headers, h) {
						return true
					}
				}
				for _, b := range bodyList {
					if strings.Contains(body, b) {
						return true
					}
				}
				return false
			},
		})
	}

	// 加载 Banner 规则
	var bannerRules []BannerRule
	for _, rule := range jsonRules.BannerRules {
		var prefix string
		if rule.HexPrefix != "" {
			decoded, err := hex.DecodeString(rule.HexPrefix)
			if err != nil {
				return fmt.Errorf("decode hex prefix %q failed: %w", rule.HexPrefix, err)
			}
			prefix = string(decoded)
		} else {
			prefix = rule.Prefix
		}

		bannerRules = append(bannerRules, BannerRule{
			Tags:   rule.Tags,
			Prefix: prefix,
		})
	}

	HTTPRules = httpRules
	BannerRules = bannerRules
	return nil
}
