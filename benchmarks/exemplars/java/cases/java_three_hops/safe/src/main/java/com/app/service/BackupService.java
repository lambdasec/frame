package com.app.service;

import com.app.io.Archive;
import java.io.IOException;

public class BackupService {
    private final Archive archive = new Archive();

    public void restore(String name) throws IOException {
        archive.extract(name);
    }
}
