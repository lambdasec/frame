package com.example.faces;

import java.util.List;
import javax.enterprise.context.ApplicationScoped;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

@ApplicationScoped
public class ItemRepository {

    @PersistenceContext
    private EntityManager em;

    @SuppressWarnings("unchecked")
    public List<Item> findByTerm(String term) {
        return em.createQuery("SELECT i FROM Item i WHERE i.name LIKE :term").setParameter("term", "%" + term + "%").getResultList();
    }

    @SuppressWarnings("unchecked")
    public List<Item> findById(String id) {
        return em.createQuery("SELECT i FROM Item i WHERE i.id = :id").setParameter("id", Long.valueOf(id)).getResultList();
    }
}
