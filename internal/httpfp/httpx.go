package httpfp

import (
	"fmt"
	"strings"

	"github.com/projectdiscovery/httpx/runner"
)

// FpResult httpx 指纹识别结果
type FpResult struct {
	URL   string   
	Proto string   
	Tags  []string // 技术栈标签，对应 nuclei 模板 tags
	Title string   // 页面 Title
	Code  int      // HTTP 状态码
}

// 返回技术栈 tags 列表，交给 PocWorker 过滤 nuclei 模板
func Probe(host string, port int) (*FpResult, error) {
	hostPort := fmt.Sprintf("%s:%d", host, port)
	fmt.Printf("[httpfp] probing %s\n", hostPort)

	var result *FpResult

	options := runner.Options{
		InputTargetHost: []string{hostPort},

		// 指纹识别开关
		TechDetect: true, 
		StatusCode: true, 
		// Title:      true, 

		NoFallbackScheme: false,
		Unsafe: false,

		Silent: true,

		OnResult: func(r runner.Result) {
			if r.Err != nil {
				return
			}

			tags := normalizeTags(r.Technologies)

			if len(tags) == 0 {
				tags = []string{"exposure", "misconfig"}
			}

			proto := "http"
			if strings.HasPrefix(r.URL, "https://") {
				proto = "https"
			}

			result = &FpResult{
				URL:   r.URL,
				Proto: proto,
				Tags:  tags,
				Title: r.Title,
				Code:  r.StatusCode,
			}

			fmt.Printf("[httpfp] %s → status=%d title=%q tech=%v\n",
				r.URL, r.StatusCode, r.Title, tags)
		},
	}

	r, err := runner.New(&options)
	if err != nil {
		return nil, fmt.Errorf("[httpfp] create runner failed: %w", err)
	}
	defer r.Close()

	r.RunEnumeration()

	if result == nil {
		// HTTP/HTTPS 均无响应 → TCP 服务（Redis/MySQL 等），使用 Banner 指纹方案
		return &FpResult{
			URL:   hostPort,
			Proto: "tcp",
			Tags:  []string{"network", "exposure"},
		}, nil
	}

	return result, nil
}

// normalizeTags 将 httpx 的 Technology 名称转换为 nuclei 模板 tags 格式
// 例如 "WordPress 6.0" → "wordpress"，"PHP/7.4" → "php"
func normalizeTags(techs []string) []string {
	tagSet := make(map[string]bool)
	for _, tech := range techs {
		// 转小写，去掉版本号（取第一个空格前的部分）
		tech = strings.ToLower(tech)
		if idx := strings.Index(tech, " "); idx > 0 {
			tech = tech[:idx]
		}
		// 去掉特殊字符
		tech = strings.ReplaceAll(tech, "/", "-")
		tech = strings.TrimSpace(tech)

		if tech != "" {
			tagSet[tech] = true

			// 技术栈别名映射（httpx 名 → nuclei tag）
			if alias, ok := techAlias[tech]; ok {
				tagSet[alias] = true
			}
		}
	}

	tags := make([]string, 0, len(tagSet))
	for t := range tagSet {
		tags = append(tags, t)
	}
	return tags
}

// techAlias httpx Technology 名称到 nuclei tags 的别名映射
// httpx 使用 wappalyzer 名称，nuclei 模板可能使用缩写
var techAlias = map[string]string{
	"apache":         "apache",
	"apache-httpd":   "apache",
	"nginx":          "nginx",
	"iis":            "iis",
	"wordpress":      "wordpress",
	"wp":             "wordpress",
	"joomla":         "joomla",
	"drupal":         "drupal",
	"laravel":        "laravel",
	"django":         "django",
	"spring":         "spring",
	"spring-boot":    "springboot",
	"tomcat":         "tomcat",
	"weblogic":       "weblogic",
	"jboss":          "jboss",
	"phpmyadmin":     "phpmyadmin",
	"elasticsearch":  "elastic",
	"jenkins":        "jenkins",
	"gitlab":         "gitlab",
	"grafana":        "grafana",
	"kibana":         "kibana",
	"shiro":          "shiro",
	"struts":         "struts",
}
