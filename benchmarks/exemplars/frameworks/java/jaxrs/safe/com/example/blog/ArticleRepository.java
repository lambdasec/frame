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
        String order = "title".equals(sort) ? "title" : "created";
        return em.createNativeQuery("SELECT * FROM article WHERE title LIKE ?1 ORDER BY " + order, Article.class)
                .setParameter(1, "%" + q + "%").getResultList();
    }

    public Article findBySlug(String slug) {
        return (Article) em.createQuery("SELECT a FROM Article a WHERE a.slug = :slug")
                .setParameter("slug", slug).getSingleResult();
    }

    @SuppressWarnings("unchecked")
    public List<Article> findByAuthor(String author) {
        return em.createQuery("SELECT a FROM Article a WHERE a.author = :author").setParameter("author", author).getResultList();
    }

    @SuppressWarnings("unchecked")
    public List<Article> findTagged(String tag, String site) {
        return em.createQuery("SELECT a FROM Article a WHERE a.tag = :tag AND a.site = :site")
                .setParameter("tag", tag).setParameter("site", site).getResultList();
    }

    @SuppressWarnings("unchecked")
    public List<Article> findDrafts(String editor) {
        return em.createQuery("SELECT a FROM Article a WHERE a.editor = :editor AND a.draft = true")
                .setParameter("editor", editor).getResultList();
    }

    @SuppressWarnings("unchecked")
    public List<Article> findByTopic(String topic) {
        return em.createNativeQuery("SELECT * FROM article WHERE topic = ?1", Article.class)
                .setParameter(1, topic).getResultList();
    }

    public void save(String title, String body) {
        em.createNativeQuery("INSERT INTO article (title, body) VALUES (?1, ?2)")
                .setParameter(1, title).setParameter(2, body).executeUpdate();
    }
}
