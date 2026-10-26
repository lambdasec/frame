package com.example.hr;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/employees")
public class EmployeeController {

    @Autowired
    private EmployeeService service;

    @GetMapping("/name/{name}")
    public List<Employee> byName(@PathVariable String name) { return service.findByName(name); }

    @GetMapping("/department")
    public List<Employee> byDepartment(@RequestParam String d) { return service.findByDepartment(d); }

    @GetMapping("/report")
    public List<Object[]> report(@RequestParam String table, @RequestParam String orderBy) {
        return service.report(table, orderBy);
    }

    @GetMapping("/filter")
    public List<Employee> filter(@RequestParam String where) { return service.filter(where); }

    @GetMapping("/city")
    public List<Employee> city(@RequestParam String city) { return service.inCity(city); }

    @GetMapping("/badge/{badge}")
    public Employee badge(@PathVariable String badge) { return service.badge(badge); }
}
