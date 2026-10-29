// Reduced from Apache Kafka (Apache-2.0), clients/.../record/internal/DefaultRecord.java at
// 4d781f506a777c43eb93b359ed8a171e032d2df4. "Bound decompressed record size (#23429)".
package org.apache.kafka.common.record.internal;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

import org.apache.kafka.common.utils.internals.ByteUtils;
import org.apache.kafka.common.utils.Utils;

public class DefaultRecord {

    public static ByteBuffer readFrom(InputStream input, int maxRecordBodySize) throws IOException {
        int sizeOfBodyInBytes = ByteUtils.readVarint(input);
        if (sizeOfBodyInBytes < 0)
            throw new IllegalStateException("negative size");
        if (sizeOfBodyInBytes > maxRecordBodySize)
            throw new IllegalStateException("exceeds max.decompressed.message.bytes");
        ByteBuffer recordBuffer = ByteBuffer.allocate(sizeOfBodyInBytes);
        Utils.readFully(input, recordBuffer);
        recordBuffer.flip();
        return recordBuffer;
    }

    public static ByteBuffer readFrom(ByteBuffer buffer) {
        int sizeOfBodyInBytes = ByteUtils.readVarint(buffer);
        if (buffer.remaining() < sizeOfBodyInBytes)
            throw new IllegalStateException("underflow");
        ByteBuffer body = ByteBuffer.allocate(sizeOfBodyInBytes);
        return body;
    }
}
