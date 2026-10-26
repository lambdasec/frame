package com.example.notes;

import java.util.List;

public class NoteService {

    private final NoteRepository repository;

    public NoteService(NoteRepository repository) {
        this.repository = repository;
    }

    public String search(String q) {
        return String.join("\n", repository.titlesLike(q));
    }

    public String find(String id) {
        return repository.body(id);
    }

    public void create(String title, String body) {
        repository.insert(title, body);
    }

    public String exportAll() {
        return String.join("\n", repository.titlesLike(""));
    }
}
