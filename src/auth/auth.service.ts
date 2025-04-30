/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from 'generated/prisma';
import * as bcrypt from 'bcrypt';
import { LoginDto, RegisterDto } from './dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';
import { stat } from 'fs';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger(AuthService.name);

  onModuleInit() {
    this.$connect();
    this.logger.log('Prisma Client connected to the database');
  }

  constructor(private readonly jwtService: JwtService) {
    super();
  }

  signJwt(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }

  async login(loginDto: LoginDto) {
    const { email, password } = loginDto;

    try {
      const user = await this.user.findUnique({
        where: { email },
      });

      if (!user) {
        throw new RpcException({
          status: 400,
          message: 'User not found',
        });
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        throw new RpcException({
          status: 400,
          message: 'Invalid password',
        });
      }

      const { password: __, ...rest } = user;

      return {
        user: rest,
        token: this.signJwt(rest),
      };
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }

  async register(registerDto: RegisterDto) {
    const { name, email, password } = registerDto;

    try {
      const existingUser = await this.user.findUnique({
        where: { email },
      });

      if (existingUser) {
        throw new RpcException({
          status: 400,
          message: 'User already exists',
        });
      }

      const user = await this.user.create({
        data: {
          name: name,
          email: email,
          password: bcrypt.hashSync(password, 10),
        },
      });

      const { password: __, ...rest } = user;

      return {
        user: rest,
        token: this.signJwt(rest),
      };
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }

  async verifyToken(token: string) {
    try {
      const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
        secret: envs.jwtSecret,
      });

      return {
        user: user,
        token: this.signJwt(user),
      };
    } catch (error) {
      throw new RpcException({
        status: 401,
        message: `Invalidad token ${error}`,
      });
    }
  }
}
