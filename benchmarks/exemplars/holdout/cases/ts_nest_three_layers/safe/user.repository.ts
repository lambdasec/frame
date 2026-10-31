import { Injectable } from '@nestjs/common';
import { DataSource } from 'typeorm';

@Injectable()
export class UserRepository {
  constructor(private readonly db: DataSource) {}
  find(name: string) {
    return this.db.query("SELECT * FROM users WHERE name = '" + name + "'");
  }
}
