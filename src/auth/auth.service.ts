import { RefreshToken } from './schemas/refresh-token.schema';
import { LoginDto } from './dto/login.dto';
import { SignupDto } from './dto/signup.dto';
import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { CreateAuthDto } from './dto/create-auth.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { User } from './schemas/user.schema';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private UserModel: Model<User>,
    @InjectModel(RefreshToken.name) private RefreshTokenModel: Model<RefreshToken>,
    private jwtService: JwtService) { }

  async signup(signupDto: SignupDto) {
    const { email, password, name } = signupDto;
    const emailInUse = await this.UserModel.findOne({
      email: email
    });
    if (emailInUse) {
      throw new BadRequestException('Email da ton tai');
    }
    const hashesPassword = await bcrypt.hash(password, 10);
    return await this.UserModel.create({
      name, email, password: hashesPassword
    });
  }

  async login(loginDto: LoginDto) {
    const { email, password } = loginDto;
    const user = await this.UserModel.findOne({ email });
    if (!user) {
      throw new BadRequestException('Sai tai khoan hoac mat khau');
    }
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      throw new BadRequestException('Sai tai khoan hoac mat khau');
    }
    const tokens = await this.generateUserTokens(user._id);
    return {
      ...tokens,
      userId: user._id
    };
  }

  async generateUserTokens(userId) {
    const accessToken = this.jwtService.sign({ userId }, { expiresIn: '1h' });
    const refreshToken = uuidv4();
    await this.storeRefreshToken(refreshToken, userId);
    return {
      accessToken,
      refreshToken
    };
  }

  async storeRefreshToken(token: string, userId) {
    const expiryDate = new Date();
    await this.RefreshTokenModel.create({ token, userId, expiryDate });
  }

  async refreshToken(refreshToken: string) {
    const token = await this.RefreshTokenModel.findOneAndDelete({
      token: refreshToken,
    });

    if (!token) {
      throw new UnauthorizedException();
    }

    return this.generateUserTokens(token.userId);
  }
}
