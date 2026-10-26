package com.example.shop;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.springframework.stereotype.Service;

@Service
public class StorageService {

    private final Path root = Paths.get("/var/uploads");

    public void save(String filename, byte[] content) throws IOException {
        Path target = root.resolve(java.util.UUID.nameUUIDFromBytes(filename.getBytes()).toString());
        Files.write(target, content);
    }
}
