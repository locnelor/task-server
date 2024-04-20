import { Module } from '@nestjs/common';
import { LoggerService } from './logger.service';
import { LoggingPlugin } from './logging.plugin';

@Module({
  providers: [LoggerService, LoggingPlugin],
  exports: [LoggerService, LoggingPlugin],
})
export class LoggerModule { }
