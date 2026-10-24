import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Inject,
  Injectable,
  SetMetadata,
  UnauthorizedException,
  createParamDecorator,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { config } from '../config.js';
import { Role, TokenPayload, verifyToken } from '../common/security.js';

export const ROLES_KEY = 'roles';
export const PUBLIC_KEY = 'public';
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);
export const Public = () => SetMetadata(PUBLIC_KEY, true);

export const CurrentUser = createParamDecorator(
  (_: unknown, ctx: ExecutionContext): TokenPayload => ctx.switchToHttp().getRequest().user,
);

/** Global guard: deny by default. Every route needs a valid token unless marked @Public(). */
@Injectable()
export class AuthGuard implements CanActivate {
  constructor(@Inject(Reflector) private readonly reflector: Reflector) {}

  canActivate(ctx: ExecutionContext): boolean {
    const targets = [ctx.getHandler(), ctx.getClass()];
    if (this.reflector.getAllAndOverride<boolean>(PUBLIC_KEY, targets)) return true;

    const req = ctx.switchToHttp().getRequest();
    const header: string | undefined = req.headers['authorization'];
    if (!header?.startsWith('Bearer ')) throw new UnauthorizedException('Missing bearer token');
    const payload = verifyToken(header.slice(7), config.jwtSecret);
    if (!payload) throw new UnauthorizedException('Invalid or expired token');
    req.user = payload;

    const roles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, targets);
    if (roles && !roles.includes(payload.role)) throw new ForbiddenException('Role not permitted');
    return true;
  }
}
