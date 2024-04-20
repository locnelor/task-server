import { Injectable } from '@nestjs/common';
import { BinaryLike, createHash } from "crypto"


@Injectable()
export class HashService {
    public md5(data: BinaryLike) {
        return createHash("md5").update(data.toString()).digest("hex")
    }
    public sha1(data: BinaryLike) {
        return createHash("sha1").update(data.toString()).digest("hex")
    }
    public cryptoPassword(data: BinaryLike) {
        return this.md5(this.sha1(`${data}`));
    }
    public createUid(args = [] as string[]) {
        return this.md5(this.sha1(`${Math.random()}_${Date.now()}_${args.join("_")}`))
    }
}
