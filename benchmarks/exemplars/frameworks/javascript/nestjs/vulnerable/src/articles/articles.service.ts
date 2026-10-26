import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { readFileSync } from 'fs';
import { Article } from './article.entity';

@Injectable()
export class ArticlesService {
  constructor(@InjectRepository(Article) private readonly repo: Repository<Article>) {}

  searchByTitle(title: string) {
    return this.repo.query("SELECT * FROM article WHERE title LIKE '%" + title + "%'");  // frame-expect: CWE-89
  }

  findByAuthor(author: string) {
    return this.repo
      .createQueryBuilder('a')
      .where("a.author = '" + author + "'")  // frame-expect: CWE-89
      .getMany();
  }

  readExport(path: string) {
    return readFileSync('/srv/exports/' + path, 'utf8');  // frame-expect: CWE-22
  }
}
