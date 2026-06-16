// Package poc 封装 nuclei 引擎，按指纹标签动态过滤模板执行 POC
package poc

import (
	"bufio"
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"unsafe"

	log "distributed-scanner/log"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

var (
	// engineCache 用于缓存加载好特定 tags 模板的 nuclei.NucleiEngine 实例
	engineCache = make(map[string]*nuclei.NucleiEngine)
	cacheMu     sync.Mutex
)

// getCacheKey 将 tags 排序后拼接成唯一的缓存 key
func getCacheKey(tags []string, pocDir string) string {
	sorted := make([]string, len(tags))
	copy(sorted, tags)
	sort.Strings(sorted)
	return pocDir + "|" + strings.Join(sorted, ",")
}

// resetEngineState 使用反射重置 nuclei.NucleiEngine 的输入源 (inputProvider) 与结果回调 (resultCallbacks)，以防在复用时数据累积污染。
func resetEngineState(e *nuclei.NucleiEngine) {
	val := reflect.ValueOf(e).Elem()

	// 1. 重置 inputProvider
	ipField := val.FieldByName("inputProvider")
	if ipField.IsValid() {
		ptr := unsafe.Pointer(ipField.UnsafeAddr())
		*(*provider.InputProvider)(ptr) = provider.NewSimpleInputProvider()
	}

	// 2. 清空 resultCallbacks
	rcField := val.FieldByName("resultCallbacks")
	if rcField.IsValid() {
		ptr := unsafe.Pointer(rcField.UnsafeAddr())
		*(*[]func(*output.ResultEvent))(ptr) = nil
	}
}

// ScanWithTags 按指纹 tags 动态过滤 nuclei 模板，只执行与目标技术栈相关的 POC
func ScanWithTags(ctx context.Context, target string, tags []string, pocDir string) ([]*output.ResultEvent, error) {
	log.Printf("[poc] scanning target=%s tags=%v\n", target, tags)

	if len(tags) == 0 {
		tags = []string{"exposure", "misconfig", "config"}
	}

	key := getCacheKey(tags, pocDir)

	cacheMu.Lock()
	engine, exists := engineCache[key]
	var err error
	if !exists {
		// 引擎不存在时才创建并加载模板
		engine, err = nuclei.NewNucleiEngineCtx(ctx,
			nuclei.WithCatalog(disk.NewCatalog(pocDir)),
			nuclei.DisableUpdateCheck(),
			nuclei.WithTemplateFilters(nuclei.TemplateFilters{
				Tags: tags,
			}),
		)
		if err == nil {
			if loadErr := engine.LoadAllTemplates(); loadErr == nil {
				engineCache[key] = engine
			} else {
				engine.Close()
				err = fmt.Errorf("load templates failed: %w", loadErr)
			}
		}
	}
	cacheMu.Unlock()

	if err != nil {
		return nil, fmt.Errorf("[poc] create or load engine failed: %w", err)
	}

	// 必须加锁保护共享引擎的执行（由于 Nuclei Engine 会被多线程的 PocWorker 复用）
	// 注意：Nuclei Engine 的 LoadTargetsFromReader 在并发调用时，其内部 inputProvider 会冲突，因此必须互斥执行扫描。
	cacheMu.Lock()
	defer cacheMu.Unlock()

	// 清空当前引擎的 targets 和 callbacks，防止上一次任务的目标残留及回调累积
	resetEngineState(engine)

	// 重新装载当前任务的 target
	reader := bufio.NewReader(strings.NewReader(target))
	engine.LoadTargetsFromReader(reader, false)

	var results []*output.ResultEvent

	// 执行扫描并注入结果收集器
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

	log.Printf("[poc] target=%s found %d findings\n", target, len(results))
	return results, nil
}
