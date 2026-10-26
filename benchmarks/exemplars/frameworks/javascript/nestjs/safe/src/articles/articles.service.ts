import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { readFileSync } from 'fs';
import { basename, join } from 'path';
import { Article } from './article.entity';

@Injectable()
export class ArticlesService {
  constructor(@InjectRepository(Article) private readonly repo: Repository<Article>) {}

  searchByTitle(title: string) {
    return this.repo.query('SELECT * FROM article WHERE title LIKE $1', ['%' + title + '%']);
  }

  findByAuthor(author: string) {
    return this.repo
      .createQueryBuilder('a')
      .where('a.author = :author', { author })
      .getMany();
  }

  readExport(path: string) {
    return readFileSync(join('/srv/exports', basename(path)), 'utf8');
  }
}
