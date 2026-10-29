package com.example.wire;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

import org.apache.kafka.common.utils.ByteUtils;

public class RecordReader {

    public ByteBuffer readBody(InputStream input) throws IOException {
        int size = ByteUtils.readVarint(input);
        ByteBuffer body = ByteBuffer.allocate(size);   // frame-expect: CWE-770
        input.read(body.array());
        return body;
    }

    public byte[] readKey(ByteBuffer buffer) {
        int keySize = ByteUtils.readVarint(buffer);
        byte[] key = new byte[keySize];   // frame-expect: CWE-770
        buffer.get(key);
        return key;
    }
}
