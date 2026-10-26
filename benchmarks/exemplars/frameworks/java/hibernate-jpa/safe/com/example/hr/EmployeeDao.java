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
        return session.createQuery("from Employee e where e.name = :name").setParameter("name", name).list();
    }

    @SuppressWarnings("unchecked")
    public List<Employee> byDepartment(String department) {
        return sessionFactory.getCurrentSession()
                .createQuery("from Employee e where e.department.name = :dept", Employee.class)
                .setParameter("dept", department)
                .getResultList();
    }

    @SuppressWarnings("unchecked")
    public List<Object[]> report(String table, String orderBy) {
        Session session = sessionFactory.openSession();
        String safeTable = "employee".equals(table) ? "employee" : "contractor";
        String safeOrder = "name".equals(orderBy) ? "name" : "id";
        try {
            return session.createSQLQuery("select id, name from " + safeTable + " order by " + safeOrder).list();
        } finally {
            session.close();
        }
    }

    @SuppressWarnings("unchecked")
    public List<Employee> filtered(String condition) {
        Session session = sessionFactory.getCurrentSession();
        Criteria criteria = session.createCriteria(Employee.class);
        criteria.add(Restrictions.sqlRestriction("{alias}.active = ?", condition.length() > 0, org.hibernate.type.BooleanType.INSTANCE));
        return criteria.list();
    }

    @SuppressWarnings("unchecked")
    public List<Employee> byCity(String city) {
        return em.createNativeQuery("SELECT * FROM employee WHERE city = ?1", Employee.class).setParameter(1, city).getResultList();
    }

    public Employee byBadge(String badge) {
        return em.createQuery("SELECT e FROM Employee e WHERE e.badge = :badge", Employee.class)
                .setParameter("badge", badge).getSingleResult();
    }
}
