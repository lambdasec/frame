package com.example.portal;

import com.opensymphony.xwork2.ActionSupport;
import java.util.List;

public class SearchAction extends ActionSupport {

    private String query;
    private String category;
    private List<Product> results;

    private final ProductDao productDao = new ProductDao();

    public String execute() {
        results = productDao.search(query, category);
        return SUCCESS;
    }

    public String getQuery() { return query; }
    public void setQuery(String query) { this.query = query; }
    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }
    public List<Product> getResults() { return results; }
}
