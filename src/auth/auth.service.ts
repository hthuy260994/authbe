import { SignupDto } from './dto/signup.dto';
import { BadRequestException, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { CreateAuthDto } from './dto/create-auth.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { User } from './schemas/user.schema';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(@InjectModel(User.name) private UserModel: Model<User>) { }

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
  create(createAuthDto: CreateAuthDto) {
    return 'This action adds a new auth';
  }

  findAll() {
    return `This action returns all auth`;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }
}
