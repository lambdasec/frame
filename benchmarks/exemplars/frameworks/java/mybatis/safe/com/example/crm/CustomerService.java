package com.example.crm;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CustomerService {

    @Autowired
    private CustomerMapper mapper;

    public Customer get(long id) {
        return mapper.byId(id);
    }

    public List<Customer> search(String term) {
        return mapper.search(term);
    }

    public List<Customer> sorted(String column, String direction) {
        String safeColumn = "id".equals(column) ? "id" : "name";
        String safeDirection = "desc".equalsIgnoreCase(direction) ? "DESC" : "ASC";
        return mapper.sorted(safeColumn, safeDirection);
    }

    public void purge(String region) {
        mapper.purgeRegion(region);
    }

    public void note(long id, String note) {
        mapper.annotate(id, note);
    }
}
