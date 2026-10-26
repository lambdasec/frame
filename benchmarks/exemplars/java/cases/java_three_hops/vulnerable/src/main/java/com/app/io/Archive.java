package com.app.io;

import java.io.IOException;

public class Archive {
    public void extract(String file) throws IOException {
        new ProcessBuilder("sh", "-c", "tar xf " + file).start();
    }
}
