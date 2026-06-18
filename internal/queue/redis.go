// Package queue 封装 Redis 队列操作
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

func (c *Client) HSet(ctx context.Context, key string, values ...interface{}) error {
	return c.rdb.HSet(ctx, key, values...).Err()
}

func (c *Client) HIncrBy(ctx context.Context, key, field string, incr int64) error {
	return c.rdb.HIncrBy(ctx, key, field, incr).Err()
}

func (c *Client) Subscribe(ctx context.Context, channel string) *redis.PubSub {
	return c.rdb.Subscribe(ctx, channel)
}

func (c *Client) Close() error {
	return c.rdb.Close()
}

func (c *Client) Del(ctx context.Context, keys ...string) error {
	return c.rdb.Del(ctx, keys...).Err()
}

func (c *Client) Ping(ctx context.Context) error {
	return c.rdb.Ping(ctx).Err()
}

func (c *Client) ReadTimeout() time.Duration {
	return c.rdb.Options().ReadTimeout
}
