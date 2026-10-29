// Reduced from Apache Kafka (Apache-2.0), clients/.../serialization/ListDeserializer.java at
// c96073e66b10055d3eeb408d950d91d7571a6126. "improve ListDeserializer (#22463)", tightened by fce22525f74b (#22514).
package org.apache.kafka.common.serialization;

import java.io.DataInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class ListDeserializer {

    private List<Integer> deserializeNullIndexList(DataInputStream dis, int length) throws IOException {
        int nullIndexListSize = dis.readInt();
        if (nullIndexListSize < 0)
            throw new IllegalStateException("negative entries");
        if (nullIndexListSize > length / Integer.BYTES)
            throw new IllegalStateException("more entries than bytes");
        List<Integer> nullIndexList = new ArrayList<>(nullIndexListSize);
        while (nullIndexListSize != 0) {
            nullIndexList.add(dis.readInt());
            nullIndexListSize--;
        }
        return nullIndexList;
    }
}
