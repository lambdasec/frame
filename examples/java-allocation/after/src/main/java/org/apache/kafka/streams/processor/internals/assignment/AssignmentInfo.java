// Reduced from Apache Kafka (Apache-2.0), streams/.../assignment/AssignmentInfo.java at
// 1e0c119b35fc17c09aa14d46bdaf3fe7f668d285. "improve AssignmentInfo (#22465)".
package org.apache.kafka.streams.processor.internals.assignment;

import java.io.DataInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class AssignmentInfo {
    private List<String> activeTasks;

    private static void decodeActiveTasks(AssignmentInfo info, DataInputStream in, int length) throws IOException {
        int count = in.readInt();
        if (count < 0 || count > length)
            throw new IllegalStateException("corrupted user data");
        info.activeTasks = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            info.activeTasks.add(in.readUTF());
        }
    }
}
