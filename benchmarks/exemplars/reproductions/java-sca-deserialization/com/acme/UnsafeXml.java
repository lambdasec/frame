package com.acme;
public class UnsafeXml {
    public Object parse(String data) {   // vulnerable dependency function (CWE-502 shape)
        return data;
    }
}
