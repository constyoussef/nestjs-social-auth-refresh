import { Body, Controller, Get, Post, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { CreateUserDto } from './dto/create-user.dto';
import { UsersService } from './users.service';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post()
  async createUser(@Body() resquest: CreateUserDto) {
    return await this.usersService.create(resquest);
  }

  @Get()
  @UseGuards(JwtAuthGuard)
  getUsers() {
    return this.usersService.getUsers();
  }
}
