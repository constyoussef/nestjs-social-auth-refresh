import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { hash } from 'bcryptjs';
import { FilterQuery, Model, UpdateQuery } from 'mongoose';
import { CreateUserDto } from './dto/create-user.dto';
import { User } from './schema/user.schema';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
  ) {}

  async create(data: CreateUserDto) {
    const user = new this.userModel({
      ...data,
      password: await hash(data.password, 10),
    });
    return await user.save();
  }

  async getUser(query: FilterQuery<User>) {
    const user = (await this.userModel.findOne(query))?.toObject();

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  async getUsers() {
    return await this.userModel.find();
  }

  async updateUser(query: FilterQuery<User>, data: UpdateQuery<User>) {
    return await this.userModel.findOneAndUpdate(query, data);
  }
}
