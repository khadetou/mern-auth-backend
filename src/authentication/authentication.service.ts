import {
  Injectable,
  ConflictException,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { User } from './schema/user.schema';
import { JwtPayload } from './jwt-payload.interface';
import { AuthCredentialsDto } from './dto/auth-credentials.dto';
import { strict } from 'assert';
import { string } from 'joi';
import { AuthUpdateCredentialsDto } from './dto/auth-update.dto';
import { Response } from 'express';

@Injectable()
export class AuthenticationService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
    private readonly configService: ConfigService,
    private jwtService: JwtService,
  ) {}

  // GET ALL USERS
  async getAllUsers(): Promise<User[]> {
    return await this.userModel.find().exec();
  }

  // GET USER BY ID
  async getUserById(id: string): Promise<User> {
    return await this.userModel.findById(id).exec();
  }

  // CREATE USER
  async createUser(authCredentialsDto: AuthCredentialsDto): Promise<User> {
    const { name, email, password } = authCredentialsDto;

    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = new this.userModel({
      name,
      email,
      password: hashedPassword,
    });
    try {
      return await user.save();
    } catch (error) {
      if (error.code === 11000) {
        throw new ConflictException('User already exists!');
      }
      throw new InternalServerErrorException();
    }
  }
  // Login /Sign In

  async signIn(
    email: string,
    password: string,
    res: Response,
  ): Promise<Omit<User, 'password'>> {
    const user = await this.userModel.findOne({ email });
    if (user && (await bcrypt.compare(password, user.password))) {
      const payload: JwtPayload = { email };
      const accessToken = this.jwtService.sign(payload);
      res.cookie('jwt', accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 30 * 24 * 60 * 60 * 1000, //30 Days
      });
      const user = await this.userModel
        .findOne({ email })
        .select('-password')
        .exec();
      return user;
    }
    throw new UnauthorizedException('Invalid credentials');
  }

  // LOG OUT
  async signOut(res: Response): Promise<{ message: string }> {
    res.clearCookie('jwt', {
      httpOnly: true,
      expires: new Date(0),
    });

    return { message: 'Logged Out successfully' };
  }

  //   FIND USER FOR SIGN IN
  async findUser(email: string): Promise<User> {
    return await this.userModel.findOne({ email }).select('-password').exec();
  }

  //   UPDATE PROFILE
  async updateUser(
    authUpdateCredentialsDto: AuthUpdateCredentialsDto,
    me: any,
  ): Promise<User> {
    const { name, email, password } = authUpdateCredentialsDto;
    const user = await this.userModel.findById(me._id).exec();
    if (user) {
      user.name = name || user.name;
      user.email = email || user.email;
      if (user.password) {
        const salt = await bcrypt.genSalt();
        user.password = await bcrypt.hash(password, salt);
      }
      try {
        return await user.save();
      } catch (error) {
        throw new InternalServerErrorException(error);
      }
    } else {
      throw new UnauthorizedException('User not found');
    }
  }
}
