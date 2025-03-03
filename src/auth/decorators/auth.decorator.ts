import { UseGuards, applyDecorators } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

import { RolProtected } from './rol-protected.decorator';
import { Role } from '@prisma/client';
import { ParentRoleGuard } from '../guards/user-role/parent-role.guard';

export function Auth(...roles: Role[]) {

  return applyDecorators(
    RolProtected(...roles),
    UseGuards(AuthGuard(), ParentRoleGuard)
  );
}