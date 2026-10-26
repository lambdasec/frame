package com.app.service;

import com.app.repo.UserRepository;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    private final UserRepository repo;

    public UserService(UserRepository repo) {
        this.repo = repo;
    }

    public List<Map<String, Object>> search(String name) {
        return repo.byName(name);
    }
}
