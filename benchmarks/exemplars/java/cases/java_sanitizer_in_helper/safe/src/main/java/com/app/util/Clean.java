package com.app.util;

public class Clean {
    public static String html(String s) {
        return org.apache.commons.text.StringEscapeUtils.escapeHtml4(s);
    }
}
