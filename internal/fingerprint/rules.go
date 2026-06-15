// Package fingerprint 定义指纹识别规则
// 将 HTTP Response 特征和 TCP Banner 特征映射为 nuclei 模板 tags
package fingerprint

import "strings"

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

// HTTPRules 从 HTTP Response Header + Body 识别技术栈
// Tags 与 nuclei 模板中的 tags 字段对应，用于动态过滤
var HTTPRules = []HTTPRule{
	{
		Tags: []string{"wordpress", "php"},
		Match: func(h, b string) bool {
			return strings.Contains(b, "wp-content") ||
				strings.Contains(b, "wp-includes") ||
				strings.Contains(b, "WordPress")
		},
	},
	{
		Tags: []string{"spring-boot", "spring", "java"},
		Match: func(h, b string) bool {
			return strings.Contains(h, "X-Application-Context") ||
				strings.Contains(b, "Whitelabel Error Page") ||
				strings.Contains(b, "Spring Framework") ||
				strings.Contains(h, "spring") ||
				// Spring Boot Actuator 常见 endpoint 响应
				strings.Contains(b, "\"status\":\"UP\"")
		},
	},
	{
		Tags: []string{"shiro", "java"},
		Match: func(h, b string) bool {
			// Apache Shiro 特征：rememberMe Cookie
			return strings.Contains(h, "Set-Cookie: rememberMe=")
		},
	},
	{
		Tags: []string{"phpmyadmin", "php"},
		Match: func(h, b string) bool {
			return strings.Contains(b, "phpMyAdmin") ||
				strings.Contains(b, "phpmyadmin")
		},
	},
	{
		Tags: []string{"php"},
		Match: func(h, b string) bool {
			return strings.Contains(h, "X-Powered-By: PHP")
		},
	},
	{
		Tags: []string{"tomcat", "java"},
		Match: func(h, b string) bool {
			return strings.Contains(h, "Server: Apache-Coyote") ||
				strings.Contains(h, "Server: Apache Tomcat") ||
				strings.Contains(b, "Apache Tomcat") ||
				strings.Contains(b, "Tomcat")
		},
	},
	{
		Tags: []string{"nginx"},
		Match: func(h, b string) bool {
			return strings.Contains(h, "Server: nginx") ||
				strings.Contains(h, "Server: openresty")
		},
	},
	{
		Tags: []string{"apache"},
		Match: func(h, b string) bool {
			return strings.Contains(h, "Server: Apache/")
		},
	},
	{
		Tags: []string{"iis", "windows"},
		Match: func(h, b string) bool {
			return strings.Contains(h, "Server: Microsoft-IIS")
		},
	},
	{
		Tags: []string{"drupal", "php"},
		Match: func(h, b string) bool {
			return strings.Contains(h, "X-Generator: Drupal") ||
				strings.Contains(b, "sites/default/files") ||
				strings.Contains(b, "Drupal.settings")
		},
	},
	{
		Tags: []string{"joomla", "php"},
		Match: func(h, b string) bool {
			return strings.Contains(b, "/components/com_") ||
				strings.Contains(b, "Joomla!")
		},
	},
	{
		Tags: []string{"laravel", "php"},
		Match: func(h, b string) bool {
			return strings.Contains(h, "Set-Cookie: laravel_session") ||
				strings.Contains(b, "Laravel")
		},
	},
	{
		Tags: []string{"django", "python"},
		Match: func(h, b string) bool {
			return strings.Contains(h, "Set-Cookie: csrftoken=") ||
				strings.Contains(b, "Django")
		},
	},
	{
		Tags: []string{"struts", "java"},
		Match: func(h, b string) bool {
			// Apache Struts 特征
			return strings.Contains(h, "X-ATG-Version") ||
				strings.Contains(b, "struts") ||
				strings.Contains(h, "Set-Cookie: STRUTS_")
		},
	},
	{
		Tags: []string{"weblogic", "java"},
		Match: func(h, b string) bool {
			return strings.Contains(h, "Server: WebLogic") ||
				strings.Contains(b, "WebLogicServer") ||
				strings.Contains(b, "BEA WebLogic")
		},
	},
	{
		Tags: []string{"jenkins"},
		Match: func(h, b string) bool {
			return strings.Contains(h, "X-Jenkins") ||
				strings.Contains(b, "Jenkins") ||
				strings.Contains(h, "Set-Cookie: JSESSIONID") && strings.Contains(b, "Jenkins")
		},
	},
	{
		Tags: []string{"grafana"},
		Match: func(h, b string) bool {
			return strings.Contains(b, "grafana") ||
				strings.Contains(b, "Grafana")
		},
	},
	{
		Tags: []string{"kibana", "elastic"},
		Match: func(h, b string) bool {
			return strings.Contains(b, "kibana") ||
				strings.Contains(b, "Kibana")
		},
	},
}

// BannerRules TCP 原始 Banner 特征匹配（非 HTTP 协议端口）
var BannerRules = []BannerRule{
	// Redis: PING 发 +PONG，未认证发 -ERR
	{Tags: []string{"redis"}, Prefix: "+PONG"},
	{Tags: []string{"redis"}, Prefix: "-ERR"},
	// MySQL: 握手包以 0x4a 开头（MySQL 5.x）或含 mysql 字样
	{Tags: []string{"mysql"}, Prefix: "J\x00\x00"},
	// MongoDB: OP_REPLY 消息头
	{Tags: []string{"mongodb"}, Prefix: "=\x00\x00\x00"},
	// Elasticsearch REST API
	{Tags: []string{"elasticsearch", "elastic"}, Prefix: "{\"name\""},
	// Memcached
	{Tags: []string{"memcached"}, Prefix: "VERSION"},
	// FTP
	{Tags: []string{"ftp"}, Prefix: "220"},
	// SSH
	{Tags: []string{"ssh"}, Prefix: "SSH-"},
	// SMTP
	{Tags: []string{"smtp"}, Prefix: "220 "},
	// RDP
	{Tags: []string{"rdp"}, Prefix: "\x03\x00\x00"},
	// Zookeeper
	{Tags: []string{"zookeeper"}, Prefix: "Zookeeper"},
}

// FallbackTags 无法识别指纹时的兜底标签，运行通用配置错误检测
var FallbackTags = []string{"exposure", "misconfig", "config"}
