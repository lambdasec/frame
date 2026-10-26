import { Controller, Get, Query } from '@nestjs/common';
import { UserService } from './user.service';

@Controller('users')
export class UserController {
  constructor(private readonly service: UserService) {}

  @Get()
  list(@Query('name') name: string) {
    return this.service.search('admin');
  }
}
