package com.app.util;

import javax.servlet.http.HttpServletRequest;

public class Params {
    public static String path(HttpServletRequest req) {
        return req.getParameter("p");
    }
}
