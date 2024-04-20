import { UserEntity } from "@app/prisma/user.entity/user.entity";
import { AuthenticationError } from "@nestjs/apollo";
import { ExecutionContext, UnauthorizedException, createParamDecorator } from "@nestjs/common";
import { ExecutionContextHost } from "@nestjs/core/helpers/execution-context-host";
import { GqlExecutionContext } from "@nestjs/graphql";
import { AuthGuard } from "@nestjs/passport";


export class JwtAuthGuard extends AuthGuard("jwt") {
  canActivate(context: ExecutionContext) {
    return super.canActivate(context);
  }

  handleRequest(err, user, info) {
    if (err || !user) {
      throw err || new UnauthorizedException();
    }
    return user;
  }
}

export class GqlAuthGuard extends AuthGuard("jwt") {
  canActivate(context: ExecutionContext) {
    const ctx = GqlExecutionContext.create(context);
    const { req } = ctx.getContext();
    return super.canActivate(
      new ExecutionContextHost([req]),
    );
  }

  handleRequest(err: any, user: any) {
    if (err || !user) {
      throw err || new AuthenticationError('请先登录！');
    }
    return user;
  }
}


export const GqlCurrentUser = createParamDecorator(
  (data: unknown, context: ExecutionContext) => {
    const ctx = GqlExecutionContext.create(context);
    return ctx.getContext().req.user;
  },
);

export const CurrentUser = createParamDecorator(
  (data: unknown, context: ExecutionContext) => {
    return context.switchToHttp().getRequest().user
  },
);
export class AuthPowerGuard extends AuthGuard("jwt") {
  constructor(
    private readonly power: PowerEnum,
    private readonly safeRange = 1,
  ) {
    super()
  }
  canActivate(context: ExecutionContext) {
    return super.canActivate(context);
  }
  handleRequest(err, user) {
    if (err || !user) {
      throw err || new UnauthorizedException("请先登录！");
    }
    const [begin, end] = this.power;
    const powers = getPowers(user.role, begin, end);
    if (powers < this.safeRange) throw new UnauthorizedException("权限不足")
    return user;
  }
}
export class GqlAuthPowerGuard extends AuthGuard("jwt") {
  constructor(
    private readonly power: PowerEnum,
    private readonly safeRange = 1,
  ) {
    super()
  }
  canActivate(context: ExecutionContext) {
    const ctx = GqlExecutionContext.create(context);
    const { req } = ctx.getContext();
    return super.canActivate(
      new ExecutionContextHost([req]),
    );
  }
  handleRequest<TUser extends UserEntity>(err: any, user: TUser) {
    if (err || !user) {
      throw err || new AuthenticationError('请先登录！');
    }
    const [begin, end] = this.power;
    const powers = getPowers(user.role, begin, end);
    if (powers < this.safeRange) throw new AuthenticationError("权限不足")
    return user;
  }
}
const getPowers = (n: number, begin: number, end: number = begin) => {
  let num = 0;
  for (let i = begin; i <= end; i++) {
    let bool = (n >> i) % 2 === 1;
    if (bool) num += Math.pow(2, i - begin);
  }
  return num;
}

//采用位判断权限。0-31有效
/**
 * [begin,end].开区间
 */
type PowerEnum = [number, number];
/**
 * 3 账号权限
 * 1  可登录                 
 * 10 可编辑信息（修改姓名、密码等）       
 * 11 可编辑他人信息
 */
export const AccountPower: PowerEnum = [0, 1];
/**
 * 7 权限大小
 * 权限优先级，111（7）为最高权限。000为失效
 * 高优先级可编辑低优先级的账号，同优先级之间不可编辑。
 */
export const PowerSize: PowerEnum = [2, 4];
