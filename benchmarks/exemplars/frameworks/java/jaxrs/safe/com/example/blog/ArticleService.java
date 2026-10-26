package com.example.blog;

import java.util.List;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

@ApplicationScoped
public class ArticleService {

    @Inject
    ArticleRepository repository;

    public List<Article> search(String q, String sort) {
        return repository.search(q, sort);
    }

    public Article bySlug(String slug) {
        return repository.findBySlug(slug);
    }

    public List<Article> byAuthor(String author) {
        return repository.findByAuthor(author);
    }

    public List<Article> tagged(String tag, String site) {
        return repository.findTagged(tag, site);
    }

    public List<Article> draftsOf(String editor) {
        return repository.findDrafts(editor);
    }

    public List<Article> byTopic(String topic) {
        return repository.findByTopic(topic);
    }

    public String landing(String key) {
        switch (key) {
            case "home": return "home";
            case "drafts": return "articles/drafts";
            default: return "";
        }
    }

    public void insert(String title, String body) {
        repository.save(title, body);
    }
}
