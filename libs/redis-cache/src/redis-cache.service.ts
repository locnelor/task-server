import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Inject, Injectable } from '@nestjs/common';
import { Cache } from "cache-manager";

@Injectable()
export class RedisCacheService {
    constructor(
        @Inject(CACHE_MANAGER) private cacheManager: Cache
    ) { }

    public get<T>(key: string) {
        return this.cacheManager.get<T>(key)
    }

    public async set(data: any, key: string, ttl?: number) {
        await this.cacheManager.set(key, data, ttl)
    }

    public async cbk<T>(callback: () => T, key: string, ttl?: number) {
        const res = await this.cacheManager.get<T>(key);
        if (!!res) return res;
        const data = await callback();
        await this.cacheManager.set(key, data, ttl)
        return data;
    }

    public del(key: string) {
        return this.cacheManager.del(key)
    }
}
