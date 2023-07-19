import {
  Body,
  Controller,
  Get,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { AuthenticationService } from './authentication.service';
import { User } from './schema/user.schema';
import { AuthCredentialsDto } from './dto/auth-credentials.dto';
import { GetUser } from './get-user-decoration';
import { Response, Request } from 'express';
import { AuthGuard } from './auth.guard';

@Controller('auth')
export class AuthenticationController {
  constructor(private readonly authService: AuthenticationService) {}

  @Get('users')
  @UseGuards(AuthGuard)
  getAllUsers(): Promise<User[]> {
    return this.authService.getAllUsers();
  }

  @Get('user')
  @UseGuards(AuthGuard)
  async getUser(@GetUser() user: User): Promise<User> {
    return user;
  }

  @Post('/signin')
  async signIn(
    @Body('email') email: string,
    @Body('password') password: string,
    @Res({ passthrough: true }) res: Response,
  ): Promise<any> {
    return this.authService.signIn(email, password, res);
  }

  @Post('/signout')
  // @UseGuards(AuthGuard)
  async signOut(@Res({ passthrough: true }) res: Response) {
    return this.authService.signOut(res);
  }

  @Post('/signup')
  async signUp(@Body() authCredentialsDto: AuthCredentialsDto): Promise<User> {
    return this.authService.createUser(authCredentialsDto);
  }
}
