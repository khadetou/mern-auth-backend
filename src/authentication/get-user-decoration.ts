import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { User } from './schema/user.schema';

export const GetUser = createParamDecorator(
  (_data, ctx: ExecutionContext): User => {
    const request = ctx.switchToHttp().getRequest();

    const user = request.user;
    console.log(user);
    return user;
  },
);
