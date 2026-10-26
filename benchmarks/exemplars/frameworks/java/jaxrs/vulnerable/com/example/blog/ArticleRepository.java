package com.example.blog;

import java.util.List;
import javax.enterprise.context.ApplicationScoped;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

@ApplicationScoped
public class ArticleRepository {

    @PersistenceContext
    EntityManager em;

    @SuppressWarnings("unchecked")
    public List<Article> search(String q, String sort) {
        String sql = "SELECT * FROM article WHERE title LIKE '%" + q + "%' ORDER BY " + sort;
        return em.createNativeQuery(sql, Article.class).getResultList();   // frame-expect: CWE-89
    }

    public Article findBySlug(String slug) {
        return (Article) em.createQuery("SELECT a FROM Article a WHERE a.slug = '" + slug + "'")   // frame-expect: CWE-89
                .getSingleResult();
    }

    @SuppressWarnings("unchecked")
    public List<Article> findByAuthor(String author) {
        return em.createQuery("SELECT a FROM Article a WHERE a.author = '" + author + "'").getResultList();   // frame-expect: CWE-89
    }

    @SuppressWarnings("unchecked")
    public List<Article> findTagged(String tag, String site) {
        StringBuilder jpql = new StringBuilder("SELECT a FROM Article a WHERE a.tag = '");
        jpql.append(tag).append("' AND a.site = '").append(site).append("'");
        return em.createQuery(jpql.toString()).getResultList();   // frame-expect: CWE-89
    }

    @SuppressWarnings("unchecked")
    public List<Article> findDrafts(String editor) {
        return em.createQuery(String.format("SELECT a FROM Article a WHERE a.editor = '%s' AND a.draft = true", editor))   // frame-expect: CWE-89
                .getResultList();
    }

    @SuppressWarnings("unchecked")
    public List<Article> findByTopic(String topic) {
        return em.createNativeQuery("SELECT * FROM article WHERE topic = '" + topic + "'", Article.class)   // frame-expect: CWE-89
                .getResultList();
    }

    public void save(String title, String body) {
        em.createNativeQuery("INSERT INTO article (title, body) VALUES ('" + title + "', '" + body + "')")   // frame-expect: CWE-89
                .executeUpdate();
    }
}
