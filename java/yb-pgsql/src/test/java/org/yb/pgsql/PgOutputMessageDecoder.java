// Copyright (c) YugabyteDB, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and limitations
// under the License.
//
package org.yb.pgsql;

import com.yugabyte.replication.LogSequenceNumber;
import java.lang.String;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.annotation.Nullable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/*
 * Test utility to decode the message streamed by the 'pgoutput' plugin as part of the Logical
 * Replication protocol.
 *
 * The format is described at
 * https://www.postgresql.org/docs/11/protocol-logicalrep-message-formats.html
 */
public class PgOutputMessageDecoder {
  private static final Logger LOG = LoggerFactory.getLogger(PgOutputMessageDecoder.class);
  public static final String IGNORED_EMPTY_STRING = "";

  public enum PgOutputMessageType { RELATION, BEGIN, COMMIT, INSERT, UPDATE };

  public interface PgOutputMessage {
    PgOutputMessageType messageType();
  }

  /*
   * RELATION message
   */
  protected static class PgOutputRelationMessage implements PgOutputMessage {
    final int oid;
    final String namespace;
    final String name;
    final char replicaIdentity;
    final List<PgOutputRelationMessageColumn> columns;

    public PgOutputRelationMessage(int oid, String namespace, String name, char replicaIdentity,
        List<PgOutputRelationMessageColumn> columns) {
      this.oid = oid;
      this.namespace = namespace;
      this.name = name;
      this.replicaIdentity = replicaIdentity;
      this.columns = columns;
    }

    public static PgOutputRelationMessage CreateForComparison(String namespace, String name,
        char replicaIdentity, List<PgOutputRelationMessageColumn> columns) {
      return new PgOutputRelationMessage(0, namespace, name, replicaIdentity, columns);
    }

    @Override
    public PgOutputMessageType messageType() {
      return PgOutputMessageType.RELATION;
    }

    @Override
    public boolean equals(Object other) {
      if (this == other)
        return true;

      if (other == null || this.getClass() != other.getClass())
        return false;

      PgOutputRelationMessage otherMessage = (PgOutputRelationMessage) other;
      return this.namespace.equals(otherMessage.namespace)
          && this.name.equals(otherMessage.name)
          && this.replicaIdentity == otherMessage.replicaIdentity
          && this.columns.equals(otherMessage.columns);
    }

    @Override
    public String toString() {
      return String.format(
          "RELATION: (name = %s, namespace = %s, replica_identity = %s, columns = %s, oid = %s)",
          name, namespace, replicaIdentity, Arrays.toString(columns.toArray()), oid);
    }
  }

  /*
   * A single column of a Relation.
   */
  protected static class PgOutputRelationMessageColumn {
    final byte flag;
    final String name;
    final int dataType;
    final int atttypmod;

    public PgOutputRelationMessageColumn(byte flag, String name, int dataType, int atttypmod) {
      this.flag = flag;
      this.name = name;
      this.dataType = dataType;
      this.atttypmod = atttypmod;
    }

    public static PgOutputRelationMessageColumn CreateForComparison(String name, int dataType) {
      return new PgOutputRelationMessageColumn((byte)0, name, dataType, 0);
    }

    @Override
    public boolean equals(Object other) {
      if (this == other)
        return true;

      if (other == null || this.getClass() != other.getClass())
        return false;

      PgOutputRelationMessageColumn otherColumn = (PgOutputRelationMessageColumn) other;
      return this.name.equals(otherColumn.name) && this.dataType == otherColumn.dataType;
    }

    @Override
    public String toString() {
      return String.format("(name = %s, data_type = %s)", name, dataType);
    }
  }

  /*
   * BEGIN message
   */
  protected static class PgOutputBeginMessage implements PgOutputMessage {
    final LogSequenceNumber finalLSN;
    final Long commitTime;
    final int transactionId;

    public PgOutputBeginMessage(
        LogSequenceNumber finalLSN, Long commitTime, int transactionId) {
      this.finalLSN = finalLSN;
      this.commitTime = commitTime;
      this.transactionId = transactionId;
    }

    public static PgOutputBeginMessage CreateForComparison(
        LogSequenceNumber finalLSN, int transactionId) {
      return new PgOutputBeginMessage(finalLSN, 0L, transactionId);
    }

    @Override
    public PgOutputMessageType messageType() {
      return PgOutputMessageType.BEGIN;
    }

    @Override
    public boolean equals(Object other) {
      if (this == other)
        return true;

      if (other == null || this.getClass() != other.getClass())
        return false;

      PgOutputBeginMessage otherMessage = (PgOutputBeginMessage) other;
      return this.finalLSN.equals(otherMessage.finalLSN)
          && this.transactionId == otherMessage.transactionId;
    }

    @Override
    public String toString() {
      return String.format(
          "BEGIN: (lsn = %s, xid = %s, commit_time = %s)", finalLSN, transactionId, commitTime);
    }
  }

  /*
   * COMMIT message
   */
  protected static class PgOutputCommitMessage implements PgOutputMessage {
    final byte flag;
    final Long commitTime;
    final LogSequenceNumber commitLSN;
    final LogSequenceNumber endLSN;

    public PgOutputCommitMessage(
        byte flag, Long commitTime, LogSequenceNumber commitLSN, LogSequenceNumber endLSN) {
      this.flag = flag;
      this.commitTime = commitTime;
      this.commitLSN = commitLSN;
      this.endLSN = endLSN;
    }

    public static PgOutputCommitMessage CreateForComparison(
        LogSequenceNumber commitLSN, LogSequenceNumber endLSN) {
      return new PgOutputCommitMessage((byte)0, 0L, commitLSN, endLSN);
    }

    @Override
    public PgOutputMessageType messageType() {
      return PgOutputMessageType.COMMIT;
    }

    @Override
    public boolean equals(Object other) {
      if (this == other)
        return true;

      if (other == null || this.getClass() != other.getClass())
        return false;

      PgOutputCommitMessage otherMessage = (PgOutputCommitMessage) other;
      return this.commitLSN.equals(otherMessage.commitLSN)
          && this.endLSN.equals(otherMessage.endLSN);
    }

    @Override
    public String toString() {
      return String.format("COMMIT: (commit_lsn = %s, end_lsn = %s, flag = %s, commit_time = %s)",
          commitLSN, endLSN, flag, commitTime);
    }
  }

  /*
   * INSERT message
   */
  protected static class PgOutputInsertMessage implements PgOutputMessage {
    final int oid;
    final PgOutputMessageTuple tuple;

    public PgOutputInsertMessage(int oid, PgOutputMessageTuple tuple) {
      this.oid = oid;
      this.tuple = tuple;
    }

    public static PgOutputInsertMessage CreateForComparison(PgOutputMessageTuple tuple) {
      return new PgOutputInsertMessage(0, tuple);
    }

    @Override
    public PgOutputMessageType messageType() {
      return PgOutputMessageType.INSERT;
    }

    @Override
    public boolean equals(Object other) {
      if (this == other)
        return true;

      if (other == null || this.getClass() != other.getClass())
        return false;

      PgOutputInsertMessage otherMessage = (PgOutputInsertMessage) other;
      return this.tuple.equals(otherMessage.tuple);
    }

    @Override
    public String toString() {
      return String.format("INSERT: (tuple = %s, oid = %s)", tuple, oid);
    }
  }

  /*
   * The tuple describing a row of data.
   */
  protected static class PgOutputMessageTuple {
    final short numColumns;
    final List<PgOutputMessageTupleColumn> columns;

    public PgOutputMessageTuple(short numColumns, List<PgOutputMessageTupleColumn> columns) {
      this.numColumns = numColumns;
      this.columns = columns;
    }

    @Override
    public boolean equals(Object other) {
      if (this == other)
        return true;

      if (other == null || this.getClass() != other.getClass())
        return false;

      PgOutputMessageTuple otherTuple = (PgOutputMessageTuple) other;
      return this.numColumns == otherTuple.numColumns && this.columns.equals(otherTuple.columns);
    }

    @Override
    public String toString() {
      return String.format(
          "(num_columns = %s, columns = %s)", numColumns, Arrays.toString(columns.toArray()));
    }
  }

  /*
   * Data of a single column present in a tuple.
   */
  protected static class PgOutputMessageTupleColumn {
    final boolean isNull;
    final boolean isToasted;
    final String textValue;

    public PgOutputMessageTupleColumn(boolean isNull, boolean isToasted, String textValue) {
      this.isNull = isNull;
      this.isToasted = isToasted;
      this.textValue = textValue;
    }

    public static PgOutputMessageTupleColumn NullValue() {
      return new PgOutputMessageTupleColumn(true, false, IGNORED_EMPTY_STRING);
    }

    public static PgOutputMessageTupleColumn ToastedValue() {
      return new PgOutputMessageTupleColumn(false, true, IGNORED_EMPTY_STRING);
    }

    public static PgOutputMessageTupleColumn TextValue(String text) {
      return new PgOutputMessageTupleColumn(false, false, text);
    }

    @Override
    public boolean equals(Object other) {
      if (this == other)
        return true;

      if (other == null || this.getClass() != other.getClass())
        return false;

      PgOutputMessageTupleColumn otherColumn = (PgOutputMessageTupleColumn) other;
      return this.isNull == otherColumn.isNull && this.isToasted == otherColumn.isToasted
          && this.textValue.equals(otherColumn.textValue);
    }

    @Override
    public String toString() {
      if (isNull) {
        return "NULL";
      } else if (isToasted) {
        return "TOASTED";
      } else {
        return textValue;
      }
    }
  }

  /*
   * UPDATE message
   */
  protected static class PgOutputUpdateMessage implements PgOutputMessage {
    final int oid;
    @Nullable final PgOutputMessageTuple old_tuple;
    final PgOutputMessageTuple new_tuple;

    public PgOutputUpdateMessage(
        int oid, @Nullable PgOutputMessageTuple old_tuple, PgOutputMessageTuple new_tuple) {
      this.oid = oid;
      this.old_tuple = old_tuple;
      this.new_tuple = new_tuple;
    }

    public static PgOutputUpdateMessage CreateForComparison(
        @Nullable PgOutputMessageTuple old_tuple, PgOutputMessageTuple new_tuple) {
      return new PgOutputUpdateMessage(0, old_tuple, new_tuple);
    }

    @Override
    public PgOutputMessageType messageType() {
      return PgOutputMessageType.UPDATE;
    }

    @Override
    public boolean equals(Object other) {
      if (this == other)
        return true;

      if (other == null || this.getClass() != other.getClass())
        return false;

      PgOutputUpdateMessage otherMessage = (PgOutputUpdateMessage) other;
      return ((this.old_tuple == null) ? otherMessage.old_tuple == null
                                       : this.old_tuple.equals(otherMessage.old_tuple))
          && this.new_tuple.equals(otherMessage.new_tuple);
    }

    @Override
    public String toString() {
      String old_tuple_string = (this.old_tuple != null) ? old_tuple.toString() : "NULL";
      return String.format(
          "UPDATE: (old_tuple = %s, new_tuple = %s, oid = %s)", old_tuple_string, new_tuple, oid);
    }
  }


  /*
   * Decode the data passed as bytes into a PgOutputMessage.
   */
  public static PgOutputMessage DecodeBytes(ByteBuffer buf) {
    final byte[] source = buf.array();
    final ByteBuffer buffer =
        ByteBuffer.wrap(Arrays.copyOfRange(source, buf.arrayOffset(), source.length));

    byte cmd = buffer.get();
    switch (cmd) {
      case 'R': // RELATION
        int oid = buffer.getInt();
        String namespace = decodeString(buffer);
        String name = decodeString(buffer);
        char replicaIdent = (char) buffer.get();
        short numAttrs = buffer.getShort();

        List<PgOutputRelationMessageColumn> columns = new ArrayList<>();
        for (int i = 0; i < numAttrs; i++) {
          byte flag = buffer.get();
          String attrName = decodeString(buffer);
          int attrId = buffer.getInt();
          int attrMode = buffer.getInt();
          columns.add(new PgOutputRelationMessageColumn(flag, attrName, attrId, attrMode));
        }

        return new PgOutputRelationMessage(oid, namespace, name, replicaIdent, columns);

      case 'B': // BEGIN
        LogSequenceNumber finalLSN = LogSequenceNumber.valueOf(buffer.getLong());
        Long commitTime = buffer.getLong();
        int transactionId = buffer.getInt();
        PgOutputBeginMessage beginMessage =
            new PgOutputBeginMessage(finalLSN, commitTime, transactionId);
        return beginMessage;

      case 'C': // COMMIT
        byte unusedFlag = buffer.get();
        LogSequenceNumber commitLSN = LogSequenceNumber.valueOf(buffer.getLong());
        LogSequenceNumber endLSN = LogSequenceNumber.valueOf(buffer.getLong());
        commitTime = buffer.getLong();
        PgOutputCommitMessage commitMessage =
            new PgOutputCommitMessage(unusedFlag, commitTime, commitLSN, endLSN);
        return commitMessage;

      case 'I': // INSERT
        oid = buffer.getInt();
        buffer.get(); // Always 'N'
        PgOutputMessageTuple tuple = decodePgOutputMessageTuple(buffer);
        PgOutputInsertMessage insertMessage = new PgOutputInsertMessage(oid, tuple);
        return insertMessage;

      case 'U': // UPDATE
        oid = buffer.getInt();
        char oldOrNew = (char)buffer.get();

        // 'K' or 'O' represents old tuple while 'N' represents new tuple
        PgOutputMessageTuple old_tuple = null;
        if (oldOrNew == 'K' || oldOrNew == 'O') {
          old_tuple = decodePgOutputMessageTuple(buffer);
          buffer.get(); // Always 'N'
        }

        PgOutputMessageTuple new_tuple = decodePgOutputMessageTuple(buffer);
        PgOutputUpdateMessage updateMessage = new PgOutputUpdateMessage(oid, old_tuple, new_tuple);
        return updateMessage;
    }

    LOG.info("Received unknown response, returning null");
    return null;
  }

  private static PgOutputMessageTuple decodePgOutputMessageTuple(ByteBuffer buffer) {
    short numColumns = buffer.getShort();
    List<PgOutputMessageTupleColumn> columns = new ArrayList<PgOutputMessageTupleColumn>();

    for (int i = 0; i < numColumns; i++) {
      byte c = buffer.get();

      switch (c) {
        case 'n':
          columns.add(PgOutputMessageTupleColumn.NullValue());
          break;
        case 'u':
          columns.add(PgOutputMessageTupleColumn.ToastedValue());
          break;
        case 't':
          int strLen = buffer.getInt();
          byte[] bytes = new byte[strLen];
          buffer.get(bytes, 0, strLen);
          String value = new String(bytes);
          columns.add(PgOutputMessageTupleColumn.TextValue(value));
          break;
      }
    }

    return new PgOutputMessageTuple(numColumns, columns);
  }

  private static String decodeString(ByteBuffer buffer) {
    StringBuffer sb = new StringBuffer();
    while (true) {
      byte c = buffer.get();
      if (c == 0) {
        break;
      }
      sb.append((char) c);
    }
    return sb.toString();
  }
}
