package main

import (
	"context"
	"errors"

	"github.com/go-redis/redis/v8"
)

var (
	Ctx    = context.Background()
	ErrNil = errors.New("No matching record found.")
)

type Database struct {
	Client *redis.Client
	// ttl    int
}

func NewDatabase(address, password string) (*Database, error) {
	opts, err := redis.ParseURL(redisUrl)
	if err != nil {
		return nil, err
	}
	client := redis.NewClient(opts)
	if err := client.Ping(Ctx).Err(); err != nil {
		return nil, err
	}
	return &Database{
		Client: client,
	}, nil
}

func (db Database) Get(key string) interface{} {
	val, err := db.Client.Get(Ctx, key).Result()
	if err != nil {
		return err
	}
	return val
}
func (db Database) Set(key string, value interface{}) error {
	err := db.Client.Set(Ctx, key, value, 0).Err()
	if err != nil {
		return err
	}
	return nil
}
