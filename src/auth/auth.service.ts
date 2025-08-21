import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { compare } from 'bcryptjs';
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

  login(user: User, response: Response) {
    const expiresAcessToken = new Date();
    expiresAcessToken.setMilliseconds(
      expiresAcessToken.getTime() +
        parseInt(
          this.configService.getOrThrow<string>(
            'JWT_ACCESS_TOKEN_EXPIRATION_MS',
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

    response.cookie('access_token', accessToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      expires: expiresAcessToken,
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
}
