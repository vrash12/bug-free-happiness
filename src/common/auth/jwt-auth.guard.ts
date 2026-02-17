// src/common/auth/jwt-auth.guard.ts
import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private jwt: JwtService) {}

  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest();
    const auth = String(req.headers['authorization'] ?? '');
    if (!auth.startsWith('Bearer ')) return false;

    const token = auth.slice('Bearer '.length);
    try {
      const payload = this.jwt.verify(token);
      req.user = payload;
      return true;
    } catch {
      return false;
    }
  }
}
