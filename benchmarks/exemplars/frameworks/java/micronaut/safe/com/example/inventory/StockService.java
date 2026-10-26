package com.example.inventory;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.util.List;

@Singleton
public class StockService {

    @Inject
    StockRepository repository;

    public List<Item> search(String q, String warehouse) {
        return repository.search(q, warehouse);
    }

    public Item bySku(String sku) {
        return repository.bySku(sku);
    }

    public void adjust(String sku, String note, String operator) {
        repository.log(sku, note, operator);
    }

    public List<Item> after(String sku) {
        return repository.after(sku);
    }

    public List<Item> byCategory(String category) {
        return repository.byCategory(category);
    }
}
