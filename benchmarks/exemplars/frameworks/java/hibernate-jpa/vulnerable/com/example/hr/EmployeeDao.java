package com.example.hr;

import java.util.List;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import org.hibernate.Criteria;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

@Repository
public class EmployeeDao {

    @Autowired
    private SessionFactory sessionFactory;

    @PersistenceContext
    private EntityManager em;

    @SuppressWarnings("unchecked")
    public List<Employee> byName(String name) {
        Session session = sessionFactory.getCurrentSession();
        return session.createQuery("from Employee e where e.name = '" + name + "'").list();   // frame-expect: CWE-89
    }

    @SuppressWarnings("unchecked")
    public List<Employee> byDepartment(String department) {
        return sessionFactory.getCurrentSession()   // frame-expect: CWE-89
                .createQuery("from Employee e where e.department.name = '" + department + "'", Employee.class)
                .getResultList();
    }

    @SuppressWarnings("unchecked")
    public List<Object[]> report(String table, String orderBy) {
        Session session = sessionFactory.openSession();
        try {
            return session.createSQLQuery("select id, name from " + table + " order by " + orderBy).list();   // frame-expect: CWE-89
        } finally {
            session.close();
        }
    }

    @SuppressWarnings("unchecked")
    public List<Employee> filtered(String condition) {
        Session session = sessionFactory.getCurrentSession();
        Criteria criteria = session.createCriteria(Employee.class);
        criteria.add(Restrictions.sqlRestriction(condition));   // frame-expect: CWE-89
        return criteria.list();
    }

    @SuppressWarnings("unchecked")
    public List<Employee> byCity(String city) {
        return em.createNativeQuery("SELECT * FROM employee WHERE city = '" + city + "'", Employee.class).getResultList();   // frame-expect: CWE-89
    }

    public Employee byBadge(String badge) {
        String jpql = "SELECT e FROM Employee e WHERE e.badge = '" + badge + "'";
        return em.createQuery(jpql, Employee.class).getSingleResult();   // frame-expect: CWE-89
    }
}
