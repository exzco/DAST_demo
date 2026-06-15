// Package poc 封装 nuclei 引擎，按指纹标签动态过滤模板执行 POC
package poc

import (
	"bufio"
	"context"
	"fmt"
	"strings"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// ScanWithTags 按指纹 tags 动态过滤 nuclei 模板，只执行与目标技术栈相关的 POC
//
// 工作原理：
//   - nuclei 模板 YAML 头中都有 tags 字段，例如 "tags: wordpress,rce"
//   - WithTemplateFilters 让 nuclei 只加载 tags 匹配的模板
//   - WordPress 站只跑 wordpress 相关模板（几十个），而非全量（数千个）
//   - 速度差异：10-100 倍
//
// pocDir: poc 模板目录路径，通常为 "../engines/dast-engine/poc" 的软链
func ScanWithTags(ctx context.Context, target string, tags []string, pocDir string) ([]*output.ResultEvent, error) {
	fmt.Printf("[poc] scanning target=%s tags=%v\n", target, tags)

	if len(tags) == 0 {
		tags = []string{"exposure", "misconfig", "config"}
	}

	engine, err := nuclei.NewNucleiEngineCtx(ctx,
		nuclei.WithCatalog(disk.NewCatalog(pocDir)),
		nuclei.DisableUpdateCheck(),
		// 核心：按指纹 tags 过滤模板，动态匹配
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{
			Tags: tags,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("[poc] create engine failed: %w", err)
	}
	defer engine.Close()

	if err := engine.LoadAllTemplates(); err != nil {
		return nil, fmt.Errorf("[poc] load templates failed: %w", err)
	}

	reader := bufio.NewReader(strings.NewReader(target))
	engine.LoadTargetsFromReader(reader, false)

	var results []*output.ResultEvent
	err = engine.ExecuteCallbackWithCtx(ctx, func(ev *output.ResultEvent) {
		if ev == nil || !ev.MatcherStatus {
			return
		}
		// 截断过大的 Response 防止 Redis 消息过大
		if len(ev.Response) > 10240 {
			ev.Response = ev.Response[:10240]
		}
		results = append(results, ev)
	})

	if err != nil {
		return results, fmt.Errorf("[poc] execute failed: %w", err)
	}

	fmt.Printf("[poc] target=%s found %d findings\n", target, len(results))
	return results, nil
}
