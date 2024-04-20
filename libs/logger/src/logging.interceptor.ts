import { PrismaService } from '@app/prisma';
import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common';
import { Observable, throwError } from 'rxjs';
import { catchError, tap } from 'rxjs/operators';
import { Request } from 'express';

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
    constructor(
        private readonly prismaService: PrismaService
    ) { }
    private getReq(context: ExecutionContext) {
        const args = context.getArgs();
        return args.find((v) => {
            if (!v) return false;
            if (!!v["req"]) return true;
            return false;
        })?.req as Request
    }
    private getId() {
        const now = Date.now();
        const random = Math.random();
        return (now + random).toString()
    }
    private async save(data: any, now: number) {
        const id = this.getId()
        const time = Date.now() - now
        await this.prismaService.logger.create({
            data: {
                id,
                time,
                ...data
            }
        }).catch(console.log)
    }
    intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
        const req = this.getReq(context);
        const name = context.getHandler().name
        const type = context.getType();
        const ip = req.ip || "null"
        const user = (req as any)?.user;
        const userId = user?.id || undefined
        const now = Date.now();
        return next
            .handle()
            .pipe(
                tap(async () => {
                    await this.save({
                        userId,
                        ip,
                        name,
                        type,
                        status: 200
                    }, now)
                }),
                catchError((err) => {
                    console.log(Object.keys(err))
                    this.save({
                        userId,
                        ip,
                        name,
                        type,
                        status: 500,
                        message: err.message?.slice(0, 200)
                    }, now)
                    return throwError(() => err)
                }),
            );
    }
}