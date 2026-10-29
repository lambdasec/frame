// Reduced from Apache Kafka (Apache-2.0), clients/.../record/internal/DefaultRecord.java at
// c130b7382c223096bba34484138c0ae761dbd1dd. Before the fix (CVE-2026-114349).
package org.apache.kafka.common.record.internal;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

import org.apache.kafka.common.utils.internals.ByteUtils;
import org.apache.kafka.common.utils.Utils;

public class DefaultRecord {

    // a record read from a decompressed batch: the size is whatever the batch says
    public static ByteBuffer readFrom(InputStream input) throws IOException {
        int sizeOfBodyInBytes = ByteUtils.readVarint(input);
        ByteBuffer recordBuffer = ByteBuffer.allocate(sizeOfBodyInBytes);
        Utils.readFully(input, recordBuffer);
        recordBuffer.flip();
        return recordBuffer;
    }

    // the ByteBuffer overload already compared the size with the bytes it has
    public static ByteBuffer readFrom(ByteBuffer buffer) {
        int sizeOfBodyInBytes = ByteUtils.readVarint(buffer);
        if (buffer.remaining() < sizeOfBodyInBytes)
            throw new IllegalStateException("underflow");
        ByteBuffer body = ByteBuffer.allocate(sizeOfBodyInBytes);
        return body;
    }
}
