import { HashService } from '@app/hash';
import { Injectable } from '@nestjs/common';
import { readFileSync } from 'fs';
import { join } from 'path';
import { cwd } from 'process';
import * as moment from "moment"

@Injectable()
export class FileService {
    constructor(
        private readonly hashService: HashService
    ) { }
    public static readonly Root = cwd();
    public static getSSLKey() {
        return readFileSync(join(this.Root, "keys", "ssh.key"))
    }
    public static getSSLPem() {
        return readFileSync(join(this.Root, "keys", "ssh.pem"))
    }
    private readonly Assets = join(FileService.Root, "assets")
}
