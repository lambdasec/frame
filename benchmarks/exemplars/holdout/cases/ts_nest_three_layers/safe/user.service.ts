import { Injectable } from '@nestjs/common';
import { UserRepository } from './user.repository';

@Injectable()
export class UserService {
  constructor(private readonly repo: UserRepository) {}
  search(name: string) {
    return this.repo.find(name);
  }
}
