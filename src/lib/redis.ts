import Redis from "ioredis";

let redisInstance: Redis | null = null;
export function getRedisInstance() {
    if (redisInstance) {
        return redisInstance;
    }
    const redis = new Redis({
        host: process.env.REDIS_HOST || 'localhost',
        port: process.env.REDIS_PORT ? parseInt(process.env.REDIS_PORT) : 6379,
        password: process.env.REDIS_PASSWORD || undefined,
        db: process.env.REDIS_DB ? parseInt(process.env.REDIS_DB) : 0,
    });
    redisInstance = redis;
    return redis;
}