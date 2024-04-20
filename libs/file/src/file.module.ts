import { Module } from '@nestjs/common';
import { FileService } from './file.service';
import { HashModule } from '@app/hash';

@Module({
  imports: [HashModule],
  providers: [FileService],
  exports: [FileService],
})
export class FileModule { }
