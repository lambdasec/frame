package com.example.crm;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/customers")
public class CustomerController {

    @Autowired
    private CustomerService service;

    @GetMapping("/{id}")
    public Customer get(@PathVariable long id) {
        return service.get(id);
    }

    @GetMapping
    public List<Customer> search(@RequestParam("q") String q,
                                 @RequestParam(value = "sort", defaultValue = "name") String sort,
                                 @RequestParam(value = "dir", defaultValue = "asc") String dir) {
        if (q != null && !q.isEmpty()) {
            return service.search(q);
        }
        return service.sorted(sort, dir);
    }

    @DeleteMapping("/region/{region}")
    public void purge(@PathVariable String region) {
        service.purge(region);
    }

    @PutMapping("/{id}/note")
    public void note(@PathVariable long id, @RequestBody String note) {
        service.note(id, note);
    }
}
