// Reduced from Apache Kafka (Apache-2.0), clients/.../serialization/ListDeserializer.java at
// d069b7cd166913fa8c571c5e9101d2697d652eb0. Before the fix (CVE-2026-111551).
package org.apache.kafka.common.serialization;

import java.io.DataInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class ListDeserializer {

    private List<Integer> deserializeNullIndexList(DataInputStream dis) throws IOException {
        int nullIndexListSize = dis.readInt();
        List<Integer> nullIndexList = new ArrayList<>(nullIndexListSize);
        while (nullIndexListSize != 0) {
            nullIndexList.add(dis.readInt());
            nullIndexListSize--;
        }
        return nullIndexList;
    }
}
