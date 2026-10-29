// Reduced from Apache Kafka (Apache-2.0), streams/.../assignment/AssignmentInfo.java at
// d069b7cd166913fa8c571c5e9101d2697d652eb0. Before the fix (CVE-2026-111551).
package org.apache.kafka.streams.processor.internals.assignment;

import java.io.DataInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class AssignmentInfo {
    private List<String> activeTasks;

    private static void decodeActiveTasks(AssignmentInfo info, DataInputStream in) throws IOException {
        int count = in.readInt();
        info.activeTasks = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            info.activeTasks.add(in.readUTF());
        }
    }
}
