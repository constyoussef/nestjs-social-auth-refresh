import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { compare, hash } from 'bcryptjs';
import { Response } from 'express';
import { User } from '../users/schema/user.schema';
import { UsersService } from '../users/users.service';
import { TokenPayload } from './types/token-payload.interface';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UsersService,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
  ) {}

  async login(user: User, response: Response) {
    const expiresAcessToken = new Date();
    expiresAcessToken.setMilliseconds(
      expiresAcessToken.getTime() +
        parseInt(
          this.configService.getOrThrow<string>(
            'JWT_ACCESS_TOKEN_EXPIRATION_MS',
          ),
        ),
    );

    const expiresRefreshToken = new Date();
    expiresRefreshToken.setMilliseconds(
      expiresRefreshToken.getTime() +
        parseInt(
          this.configService.getOrThrow<string>(
            'JWT_REFRESH_TOKEN_EXPIRATION_MS',
          ),
        ),
    );

    const tokenPayload: TokenPayload = {
      userId: user._id.toHexString(),
    };
    const accessToken = this.jwtService.sign(tokenPayload, {
      secret: this.configService.getOrThrow<string>('JWT_ACCESS_TOKEN_SECRET'),
      expiresIn: `${this.configService.getOrThrow<string>(
        'JWT_ACCESS_TOKEN_EXPIRATION_MS',
      )}ms`,
    });
    const refreshToken = this.jwtService.sign(tokenPayload, {
      secret: this.configService.getOrThrow<string>('JWT_REFRESH_TOKEN_SECRET'),
      expiresIn: `${this.configService.getOrThrow<string>(
        'JWT_REFRESH_TOKEN_EXPIRATION_MS',
      )}ms`,
    });

    await this.userService.updateUser(
      {
        _id: user._id,
      },
      {
        $set: {
          refreshToken: await hash(refreshToken, 10),
        },
      },
    );

    response.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      expires: expiresAcessToken,
    });
    response.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      expires: expiresRefreshToken,
    });
  }

  async verifyUser(email: string, password: string) {
    try {
      const user = await this.userService.getUser({ email });

      const authenticated = await compare(password, user.password);

      if (!authenticated) {
        throw new UnauthorizedException('Invalid credentials');
      }
      return user;
    } catch (error) {
      console.log(error);
      throw new UnauthorizedException('Invalid credentials');
    }
  }

  async verifyUserRefreshToken(refreshToken: string, userId: string) {
    try {
      const user = await this.userService.getUser({ _id: userId });

      if (!user.refreshToken) {
        throw new UnauthorizedException('Invalid credentials');
      }
      const authenticated = await compare(refreshToken, user.refreshToken);
      if (!authenticated) {
        throw new UnauthorizedException();
      }
      return user;
    } catch (error) {
      console.log(error);
      throw new UnauthorizedException('Refresh token is invalid');
    }
  }
}
