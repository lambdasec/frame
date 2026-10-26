import { Injectable } from '@nestjs/common';

@Injectable()
export class UserRepository {
  constructor(private readonly db: any) {}
  find(name: string) {
    return this.db.query("SELECT * FROM users WHERE name = '" + name + "'");
  }
}
