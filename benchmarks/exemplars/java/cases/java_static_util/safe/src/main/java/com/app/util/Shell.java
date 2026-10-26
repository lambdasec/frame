package com.app.util;

import java.io.IOException;

public final class Shell {
    private Shell() {}

    public static Process run(String cmd) throws IOException {
        return Runtime.getRuntime().exec("sh -c " + cmd);
    }
}
