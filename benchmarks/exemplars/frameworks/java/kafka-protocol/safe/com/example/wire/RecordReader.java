package com.example.wire;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

import org.apache.kafka.common.utils.ByteUtils;

public class RecordReader {
    private final int maxRecordBytes;

    public RecordReader(int maxRecordBytes) {
        this.maxRecordBytes = maxRecordBytes;
    }

    public ByteBuffer readBody(InputStream input) throws IOException {
        int size = ByteUtils.readVarint(input);
        if (size < 0 || size > maxRecordBytes)
            throw new IOException("record size out of range: " + size);
        ByteBuffer body = ByteBuffer.allocate(size);
        input.read(body.array());
        return body;
    }

    public byte[] readKey(ByteBuffer buffer) {
        int keySize = ByteUtils.readVarint(buffer);
        if (keySize < 0 || buffer.remaining() < keySize)
            throw new IllegalStateException("key larger than the record");
        byte[] key = new byte[keySize];
        buffer.get(key);
        return key;
    }
}
