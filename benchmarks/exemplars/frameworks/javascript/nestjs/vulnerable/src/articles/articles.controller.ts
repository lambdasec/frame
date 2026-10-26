import { Controller, Get, Post, Query, Param, Body, Headers, Res } from '@nestjs/common';
import { Response } from 'express';
import { ArticlesService } from './articles.service';

@Controller('articles')
export class ArticlesController {
  constructor(private readonly articles: ArticlesService) {}

  @Get('search')
  search(@Query('title') title: string) {
    return this.articles.searchByTitle(title);
  }

  @Get('by-author/:author')
  byAuthor(@Param('author') author: string) {
    return this.articles.findByAuthor(author);
  }

  @Post('import')
  importFrom(@Body() body: { path: string }) {
    return this.articles.readExport(body.path);
  }

  @Get('banner')
  banner(@Headers('x-banner') banner: string, @Res() res: Response) {
    res.send('<div class="banner">' + banner + '</div>');  // frame-expect: CWE-79
  }
}
