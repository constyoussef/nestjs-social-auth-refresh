import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { User } from 'src/users/schema/user.schema';

const getCurrentUserByContext = (context: ExecutionContext) =>
  context.switchToHttp().getRequest<{ user: User }>().user;

export const CurrentUser = createParamDecorator(
  (_data: unknown, context: ExecutionContext) =>
    getCurrentUserByContext(context),
);
