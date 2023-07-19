import { IsEmail, IsOptional, IsString } from 'class-validator';

export class AuthUpdateCredentialsDto {
  @IsString()
  @IsOptional()
  name: string;
  @IsString()
  @IsOptional()
  password: string;
  @IsEmail()
  @IsOptional()
  email: string;
}
