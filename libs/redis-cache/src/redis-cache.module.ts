import { Module } from '@nestjs/common';
import { RedisCacheService } from './redis-cache.service';
import { CacheModule } from '@nestjs/cache-manager';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { redisStore } from 'cache-manager-redis-store';

@Module({
  imports: [
    CacheModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      // @ts-ignore
      useFactory: (config: ConfigService) => {
        return ({
          store: async () => await redisStore({
            socket: {
              host: config.get("REDIS_HOST"),
              port: config.get("REDIS_PORT")
            },
            password: config.get("REDIS_PASSWORD"),
            ttl: config.get("CACHE_TTL"),
          }),
        })
      }
    }),
  ],
  providers: [RedisCacheService],
  exports: [RedisCacheService],
})
export class RedisCacheModule { }
