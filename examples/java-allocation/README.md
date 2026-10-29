# Allocations sized by a peer (Java, CWE-770)

Three places in Apache Kafka read a length or a count off the wire and allocated that much before checking it: a record batch that declares a 2 GiB record body makes a consumer, a broker handler or the log cleaner call `ByteBuffer.allocate(2_000_000_000)` and die with `OutOfMemoryError`. `before/` holds each method reduced from the Kafka commit before its fix, `after/` from the fix (the commits are named in each file's header; Kafka is Apache-2.0):

| File | Size read with | Allocated by | Fix |
|------|----------------|--------------|-----|
| `DefaultRecord.readFrom(InputStream)` | Kafka's `ByteUtils.readVarint` | `ByteBuffer.allocate` | [4d781f5](https://github.com/apache/kafka/commit/4d781f506a777c43eb93b359ed8a171e032d2df4) |
| `ListDeserializer.deserializeNullIndexList` | `DataInputStream.readInt` | `new ArrayList<>(n)` | [c96073e](https://github.com/apache/kafka/commit/c96073e66b10055d3eeb408d950d91d7571a6126) |
| `AssignmentInfo.decodeActiveTasks` | `DataInputStream.readInt` | `new ArrayList<>(n)` | [1e0c119](https://github.com/apache/kafka/commit/1e0c119b35fc17c09aa14d46bdaf3fe7f668d285) |

Kafka's advisory lists CVE-2026-114349 (the record reader) and CVE-2026-111551 (`ListDeserializer`, Streams' `AssignmentInfo`), fixed in 4.2.2, 4.3.2 and 4.4.0. The fix commits do not cite the ids; they are matched to them by the components the advisory names.

```bash
cd examples/java-allocation
```

## Before the fixes

```console
$ frame scan before --root .
   Location: before/src/main/java/org/apache/kafka/common/record/internal/DefaultRecord.java:17:19
   Function: DefaultRecord.readFrom
   Description: Tainted data from '$sizeOfBodyInBytes' flows to alloc_size sink
   ...
   Location: before/src/main/java/org/apache/kafka/common/serialization/ListDeserializer.java:14:54
   Function: ListDeserializer.deserializeNullIndexList
   ...
   Location: before/src/main/java/org/apache/kafka/streams/processor/internals/assignment/AssignmentInfo.java:15:43
   Function: AssignmentInfo.decodeActiveTasks
   ...
Scanned 3 files: 3 findings (3 medium)
```

A number read off a binary stream or buffer (`DataInputStream` / `DataInput` / `ObjectInputStream` / `RandomAccessFile` `readInt`, `readLong`, `readShort`, `readUnsignedShort`, ...; `ByteBuffer.getInt`, ...) is a `wire_size` source: what the peer sent. It is not text, so it is reported only where it sizes an allocation (an array dimension, `ByteBuffer.allocate`, a capacity constructor such as `new ArrayList<>(n)` or `new HashMap<>(n)` when the argument is an integer; with a collection or a String those constructors copy), never at an injection sink. Request data parsed to a number (`Integer.parseInt(req.getParameter("n"))`) is still attacker data there.

`DefaultRecord`'s size comes from Kafka's own `ByteUtils`, which the `kafka-protocol` pack makes a `wire_size` source (both its 3.x package and the later `internals` one); without packs that finding is missed:

```console
$ frame scan before --root . --no-packs
Scanned 3 files: 2 findings (2 medium)
```

The other overload, `readFrom(ByteBuffer)`, compared the size with the bytes it had (`buffer.remaining() < size` then throw) and is not reported.

## After the fixes

```console
$ frame scan after --root .
Scanned 3 files: 0 findings (none)
```

Any branch condition on the path that mentions the size counts as bounding it (`if (n < 0 || n > max) throw`, `if (n > length / Integer.BYTES)`, a comparison with the bytes available), and so does `Math.min(n, limit)`. Frame does not judge whether a limit is small enough: that is a policy question, and answering it would turn every deliberate limit into a finding.

See [docs/coverage.md](../../docs/coverage.md) and the pack in `frame/sil/packs/data/java/kafka-protocol.toml`.
