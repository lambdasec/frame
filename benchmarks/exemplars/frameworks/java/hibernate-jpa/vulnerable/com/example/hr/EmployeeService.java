package com.example.hr;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class EmployeeService {

    @Autowired
    private EmployeeDao dao;

    public List<Employee> findByName(String name) { return dao.byName(name); }
    public List<Employee> findByDepartment(String d) { return dao.byDepartment(d); }
    public List<Object[]> report(String table, String orderBy) { return dao.report(table, orderBy); }
    public List<Employee> filter(String condition) { return dao.filtered(condition); }
    public List<Employee> inCity(String city) { return dao.byCity(city); }
    public Employee badge(String badge) { return dao.byBadge(badge); }
}
