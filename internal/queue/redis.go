// Package queue 封装 Redis 队列操作
// 所有节点（Dispatcher / Worker）通过此包与中心 Redis 通信
package queue

import (
	"context"
	"fmt"
	"time"

	"distributed-scanner/internal/config"
	log "distributed-scanner/log"

	"github.com/redis/go-redis/v9"
)

type Client struct {
	rdb *redis.Client
}

func NewClient(redisCfg config.RedisConfig) *Client {
	rdb := redis.NewClient(&redis.Options{
		Addr:        redisCfg.Addr,
		Password:    redisCfg.Password,
		DB:          redisCfg.DB,
		DialTimeout: redisCfg.DialTimeout,
		ReadTimeout: redisCfg.ReadTimeout,
	})
	ctx, cancel := context.WithTimeout(context.Background(), redisCfg.DialTimeout)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		panic(fmt.Sprintf("[queue] redis connect failed addr=%s err=%v", redisCfg.Addr, err))
	}
	log.Printf("[queue] redis connected: %s (db=%d)\n", redisCfg.Addr, redisCfg.DB)
	return &Client{rdb: rdb}
}

func (c *Client) Push(ctx context.Context, key, value string) error {
	return c.rdb.RPush(ctx, key, value).Err()
}

func (c *Client) BLPop(ctx context.Context, key string) (string, error) {
	res, err := c.rdb.BLPop(ctx, 0, key).Result()
	if err != nil {
		return "", err
	}
	if len(res) < 2 {
		return "", fmt.Errorf("blpop: unexpected result length %d", len(res))
	}
	return res[1], nil
}

// HSet 更新 Hash 中的字段（用于记录进度 scan:status:{taskId}）
func (c *Client) HSet(ctx context.Context, key string, values ...interface{}) error {
	return c.rdb.HSet(ctx, key, values...).Err()
}

// HIncrBy 自增 Hash 字段（用于统计各阶段完成数量）
func (c *Client) HIncrBy(ctx context.Context, key, field string, incr int64) error {
	return c.rdb.HIncrBy(ctx, key, field, incr).Err()
}

// Subscribe 订阅控制频道（用于接收取消/暂停命令）
func (c *Client) Subscribe(ctx context.Context, channel string) *redis.PubSub {
	return c.rdb.Subscribe(ctx, channel)
}

// Close 关闭 Redis 连接
func (c *Client) Close() error {
	return c.rdb.Close()
}

// Ping 检查连通性，用于健康检查
func (c *Client) Ping(ctx context.Context) error {
	return c.rdb.Ping(ctx).Err()
}

// ReadTimeout 对外暴露，供 BLPop 等超时判断
func (c *Client) ReadTimeout() time.Duration {
	return c.rdb.Options().ReadTimeout
}
