import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { AuthenticationService } from './authentication.service';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private config: ConfigService,
    private readonly authService: AuthenticationService,
  ) {}
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>();

    const token = req.cookies.jwt;

    if (!token) {
      throw new UnauthorizedException('You are not logged in');
    }
    try {
      const payload = await this.jwtService.verifyAsync(token, {
        secret: this.config.get('JWT_SECRET'),
      });
      req['user'] = payload;
      const decoded = this.jwtService.verify(token);

      req.user = this.authService.findUser(decoded.email);
    } catch (error) {
      throw new UnauthorizedException(error);
    }
    return true;
  }
}
