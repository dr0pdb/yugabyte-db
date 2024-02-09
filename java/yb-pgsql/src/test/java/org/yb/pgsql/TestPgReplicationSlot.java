// Copyright (c) YugabyteDB, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.  You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied.  See the License for the specific language governing permissions and limitations
// under the License.
//
package org.yb.pgsql;

import static org.yb.AssertionWrappers.assertEquals;
import static org.yb.AssertionWrappers.assertTrue;
import static org.yb.AssertionWrappers.fail;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yb.YBTestRunner;
import org.yb.pgsql.PgOutputMessageDecoder.*;

import com.yugabyte.PGConnection;
import com.yugabyte.replication.LogSequenceNumber;
import com.yugabyte.replication.PGReplicationConnection;
import com.yugabyte.replication.PGReplicationStream;
import com.yugabyte.util.PSQLException;

@RunWith(value = YBTestRunner.class)
public class TestPgReplicationSlot extends BasePgSQLTest {
  private static final Logger LOG = LoggerFactory.getLogger(TestPgReplicationSlot.class);
  private static final boolean NOT_NULL = false;
  private static final boolean NULL = true;
  private static final boolean NOT_TOASTED = false;
  private static final boolean TOASTED = true;

  @Override
  protected int getInitialNumTServers() {
    return 3;
  }

  @Override
  protected Map<String, String> getTServerFlags() {
    Map<String, String> flagMap = super.getTServerFlags();
    flagMap.put("allowed_preview_flags_csv",
        "ysql_yb_enable_replication_commands,yb_enable_cdc_consistent_snapshot_streams");
    flagMap.put("ysql_yb_enable_replication_commands", "true");
<<<<<<< HEAD
<<<<<<< HEAD
    flagMap.put("ysql_TEST_enable_replication_slot_consumption", "true");
    flagMap.put("yb_enable_cdc_consistent_snapshot_streams", "true");
    flagMap.put("vmodule", "cdc_service=4,cdcsdk_producer=4");
    flagMap.put("yb_enable_cdc_consistent_snapshot_streams", "true");
=======
>>>>>>> 81e79e9736 (Remove restriction of enabling consistent snapshot streams)
=======
    flagMap.put("ysql_TEST_enable_replication_slot_consumption", "true");
    flagMap.put("vmodule", "cdc_service=4,cdcsdk_producer=4");
>>>>>>> 9c106d26b2 (Introduce MVP support to consume changes via ReplicationSlot and Walsender)
    return flagMap;
  }

  @Override
  protected Map<String, String> getMasterFlags() {
    Map<String, String> flagMap = super.getMasterFlags();
    flagMap.put("allowed_preview_flags_csv",
        "ysql_yb_enable_replication_commands,yb_enable_cdc_consistent_snapshot_streams");
    flagMap.put("ysql_yb_enable_replication_commands", "true");
<<<<<<< HEAD
<<<<<<< HEAD
    flagMap.put("ysql_TEST_enable_replication_slot_consumption", "true");
    flagMap.put("yb_enable_cdc_consistent_snapshot_streams", "true");
=======
>>>>>>> 81e79e9736 (Remove restriction of enabling consistent snapshot streams)
=======
    flagMap.put("yb_enable_cdc_consistent_snapshot_streams", "true");
>>>>>>> 518671e594 (temp)
    return flagMap;
  }

  @Test
  public void createAndDropFromDifferentTservers() throws Exception {
    Connection conn1 = getConnectionBuilder().withTServer(0).connect();
    Connection conn2 = getConnectionBuilder().withTServer(1).connect();

    try (Statement statement = conn1.createStatement()) {
      statement.execute("select pg_create_logical_replication_slot('test_slot', 'pgoutput')");
    }
    try (Statement statement = conn2.createStatement()) {
      statement.execute("select pg_drop_replication_slot('test_slot')");
    }
    try (Statement statement = conn1.createStatement()) {
      statement.execute("select pg_create_logical_replication_slot('test_slot', 'pgoutput')");
    }
    try (Statement statement = conn2.createStatement()) {
      statement.execute("select pg_drop_replication_slot('test_slot')");
    }
  }

  @Test
  public void replicationConnectionCreateDrop() throws Exception {
    Connection conn =
        getConnectionBuilder().withTServer(0).replicationConnect();
    PGReplicationConnection replConnection = conn.unwrap(PGConnection.class).getReplicationAPI();

    replConnection.createReplicationSlot()
        .logical()
        .withSlotName("test_slot_repl_conn")
        .withOutputPlugin("pgoutput")
        .make();
    replConnection.dropReplicationSlot("test_slot_repl_conn");
  }

  @Test
  public void replicationConnectionCreateTemporaryUnsupported() throws Exception {
    Connection conn = getConnectionBuilder().withTServer(0).replicationConnect();
    PGReplicationConnection replConnection = conn.unwrap(PGConnection.class).getReplicationAPI();

    String expectedErrorMessage = "Temporary replication slot is not yet supported";

    boolean exceptionThrown = false;
    try {
      replConnection.createReplicationSlot()
          .logical()
          .withSlotName("test_slot_repl_conn_temporary")
          .withOutputPlugin("pgoutput")
          .withTemporaryOption()
          .make();
    } catch (PSQLException e) {
      exceptionThrown = true;
      if (StringUtils.containsIgnoreCase(e.getMessage(), expectedErrorMessage)) {
        LOG.info("Expected exception", e);
      } else {
        fail(String.format("Unexpected Error Message. Got: '%s', Expected to contain: '%s'",
            e.getMessage(), expectedErrorMessage));
      }
    }

    assertTrue("Expected an exception but wasn't thrown", exceptionThrown);
  }

  @Test
  public void replicationConnectionCreatePhysicalUnsupported() throws Exception {
    Connection conn = getConnectionBuilder().withTServer(0).replicationConnect();
    PGReplicationConnection replConnection = conn.unwrap(PGConnection.class).getReplicationAPI();

    String expectedErrorMessage = "YSQL only supports logical replication slots";

    boolean exceptionThrown = false;
    try {
      replConnection.createReplicationSlot()
          .physical()
          .withSlotName("test_slot_repl_conn_temporary")
          .make();
    } catch (PSQLException e) {
      exceptionThrown = true;
      if (StringUtils.containsIgnoreCase(e.getMessage(), expectedErrorMessage)) {
        LOG.info("Expected exception", e);
      } else {
        fail(String.format("Unexpected Error Message. Got: '%s', Expected to contain: '%s'",
            e.getMessage(), expectedErrorMessage));
      }
    }

    assertTrue("Expected an exception but wasn't thrown", exceptionThrown);
  }

  private List<PgOutputMessage> receiveMessage(PGReplicationStream stream, int count)
      throws SQLException {
    List<PgOutputMessage> result = new ArrayList<PgOutputMessage>(count);
    for (int index = 0; index < count; index++) {
      PgOutputMessage message = PgOutputMessageDecoder.DecodeBytes(stream.read());
      result.add(message);
    }

    return result;
  }

  // TODO(#20726): Add more test cases covering:
  // 1. INSERTs in a BEGIN/COMMIT block
  // 2. Single shard transactions
  // 3. Transactions with savepoints (commit/abort subtxns)
  // 4. Transactions after table rewrite operations like ADD PRIMARY KEY

  @Test
  public void replicationConnectionConsumption() throws Exception {
    try (Statement stmt = connection.createStatement()) {
      stmt.execute("CREATE TABLE t1 (a int primary key, b text, c bool) SPLIT INTO 1 TABLETS");
      stmt.execute("CREATE PUBLICATION pub FOR ALL TABLES");
    }

    Connection conn =
        getConnectionBuilder().withTServer(0).replicationConnect();
    PGReplicationConnection replConnection = conn.unwrap(PGConnection.class).getReplicationAPI();

    replConnection.createReplicationSlot()
        .logical()
        .withSlotName("test_slot_repl_conn")
        .withOutputPlugin("pgoutput")
        .make();

    try (Statement stmt = connection.createStatement()) {
      stmt.execute("INSERT INTO t1 VALUES(1, 'abcd', true)");
      stmt.execute("INSERT INTO t1 VALUES(2, 'defg', true)");
      stmt.execute("INSERT INTO t1 VALUES(3, 'hijk', false)");
      stmt.execute("UPDATE t1 SET b = 'updated_abcd' WHERE a = 1");
      stmt.execute("UPDATE t1 SET b = NULL, c = false WHERE a = 2");
    }

    PGReplicationStream stream = replConnection.replicationStream()
                                     .logical()
                                     .withSlotName("test_slot_repl_conn")
                                     .withStartPosition(LogSequenceNumber.valueOf(0L))
                                     .withSlotOption("proto_version", 1)
                                     .withSlotOption("publication_names", "pub")
                                     .start();

    List<PgOutputMessage> result = new ArrayList<PgOutputMessage>();
<<<<<<< HEAD
<<<<<<< HEAD
    // 1 Relation, 3 * 3 (begin, insert and commit), 3 * 2 (begin, update and commit).
    result.addAll(receiveMessage(stream, 16));
=======
    // 1 Relation, 3 * 3 (begin, insert and commit).
    result.addAll(receiveMessage(stream, 10));
>>>>>>> 9c106d26b2 (Introduce MVP support to consume changes via ReplicationSlot and Walsender)
=======
    // 1 Relation, 3 * 3 (begin, insert and commit), 3 * 2 (begin, update and commit).
    result.addAll(receiveMessage(stream, 16));
>>>>>>> e61807f685 (Introduce support for update operation)
    for (PgOutputMessage res : result) {
      LOG.info("Row = {}", res);
    }

    // TODO(#20726): Add comments on the choice of LSN values once we have integrated with
    // GetConsistentChanges RPC. This requires the implementation of the LSN generator to be
    // completed.
    List<PgOutputMessage> expectedResult = new ArrayList<PgOutputMessage>() {
      {
        add(PgOutputBeginMessage.CreateForComparison(LogSequenceNumber.valueOf("0/4"), 1));
        add(PgOutputRelationMessage.CreateForComparison("public", "t1", 'd',
            Arrays.asList(PgOutputRelationMessageColumn.CreateForComparison("a", 23),
<<<<<<< HEAD
<<<<<<< HEAD
                PgOutputRelationMessageColumn.CreateForComparison("b", 25),
                PgOutputRelationMessageColumn.CreateForComparison("c", 16))));
        add(PgOutputInsertMessage.CreateForComparison(new PgOutputMessageTuple((short) 3,
            Arrays.asList(
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "1"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "abcd"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "t")))));
=======
                PgOutputRelationMessageColumn.CreateForComparison("b", 25))));
        add(PgOutputInsertMessage.CreateForComparison(new PgOutputMessageTuple((short) 2,
            Arrays.asList(
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "1"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "abcd")))));
>>>>>>> 9c106d26b2 (Introduce MVP support to consume changes via ReplicationSlot and Walsender)
=======
                PgOutputRelationMessageColumn.CreateForComparison("b", 25),
                PgOutputRelationMessageColumn.CreateForComparison("c", 16))));
        add(PgOutputInsertMessage.CreateForComparison(new PgOutputMessageTuple((short) 3,
            Arrays.asList(
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "1"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "abcd"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "t")))));
>>>>>>> e61807f685 (Introduce support for update operation)
        add(PgOutputCommitMessage.CreateForComparison(
            LogSequenceNumber.valueOf("0/4"), LogSequenceNumber.valueOf("0/5")));

        add(PgOutputBeginMessage.CreateForComparison(LogSequenceNumber.valueOf("0/7"), 1));
<<<<<<< HEAD
<<<<<<< HEAD
        add(PgOutputInsertMessage.CreateForComparison(new PgOutputMessageTuple((short) 3,
            Arrays.asList(
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "2"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "defg"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "t")))));
=======
        add(PgOutputInsertMessage.CreateForComparison(new PgOutputMessageTuple((short) 2,
            Arrays.asList(
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "2"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "defg")))));
>>>>>>> 9c106d26b2 (Introduce MVP support to consume changes via ReplicationSlot and Walsender)
=======
        add(PgOutputInsertMessage.CreateForComparison(new PgOutputMessageTuple((short) 3,
            Arrays.asList(
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "2"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "defg"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "t")))));
>>>>>>> e61807f685 (Introduce support for update operation)
        add(PgOutputCommitMessage.CreateForComparison(
            LogSequenceNumber.valueOf("0/7"), LogSequenceNumber.valueOf("0/8")));

        add(PgOutputBeginMessage.CreateForComparison(LogSequenceNumber.valueOf("0/A"), 1));
<<<<<<< HEAD
<<<<<<< HEAD
        add(PgOutputInsertMessage.CreateForComparison(new PgOutputMessageTuple((short) 3,
            Arrays.asList(
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "3"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "hijk"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "f")))));
        add(PgOutputCommitMessage.CreateForComparison(
            LogSequenceNumber.valueOf("0/A"), LogSequenceNumber.valueOf("0/B")));

        add(PgOutputBeginMessage.CreateForComparison(LogSequenceNumber.valueOf("0/D"), 1));
        add(PgOutputUpdateMessage.CreateForComparison(
            new PgOutputMessageTuple((short) 3,
                Arrays.asList(new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "1"),
                    new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "abcd"),
                    new PgOutputMessageTupleColumn(
                        NOT_NULL, TOASTED, PgOutputMessageDecoder.IGNORED_EMPTY_STRING))),
            new PgOutputMessageTuple((short) 3,
                Arrays.asList(new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "1"),
                    new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "updated_abcd"),
                    new PgOutputMessageTupleColumn(
                        NOT_NULL, TOASTED, PgOutputMessageDecoder.IGNORED_EMPTY_STRING)))));
        add(PgOutputCommitMessage.CreateForComparison(
            LogSequenceNumber.valueOf("0/D"), LogSequenceNumber.valueOf("0/E")));

        add(PgOutputBeginMessage.CreateForComparison(LogSequenceNumber.valueOf("0/10"), 1));
        add(PgOutputUpdateMessage.CreateForComparison(
            new PgOutputMessageTuple((short) 3,
                Arrays.asList(new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "2"),
                    new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "defg"),
                    new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "t"))),
            new PgOutputMessageTuple((short) 3,
                Arrays.asList(new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "2"),
                    new PgOutputMessageTupleColumn(
                        NULL, NOT_TOASTED, PgOutputMessageDecoder.IGNORED_EMPTY_STRING),
                    new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "f")))));
        add(PgOutputCommitMessage.CreateForComparison(
            LogSequenceNumber.valueOf("0/10"), LogSequenceNumber.valueOf("0/11")));
      }
    };
    assertEquals(expectedResult, result);

    stream.close();
  }

  @Test
  public void replicationConnectionConsumptionAllDataTypes() throws Exception {
    String create_stmt = "CREATE TABLE test_table ( "
        + "a INT PRIMARY KEY, "
        + "col_bit BIT(6), "
        + "col_boolean BOOLEAN, "
        + "col_box BOX, "
        + "col_bytea BYTEA, "
        + "col_cidr CIDR, "
        + "col_circle CIRCLE, "
        + "col_date DATE, "
        + "col_float FLOAT, "
        + "col_double DOUBLE PRECISION, "
        + "col_inet INET, "
        + "col_int INT, "
        + "col_json JSON, "
        + "col_jsonb JSONB, "
        + "col_line LINE, "
        + "col_lseg LSEG, "
        + "col_macaddr8 MACADDR8, "
        + "col_macaddr MACADDR, "
        + "col_money MONEY, "
        + "col_numeric NUMERIC, "
        + "col_path PATH, "
        + "col_point POINT, "
        + "col_polygon POLYGON, "
        + "col_text TEXT, "
        + "col_time TIME, "
        + "col_timestamp TIMESTAMP, "
        + "col_timetz TIMETZ, "
        + "col_uuid UUID, "
        + "col_varbit VARBIT(10), "
        + "col_timestamptz TIMESTAMPTZ, "
        + "col_int4range INT4RANGE, "
        + "col_int8range INT8RANGE, "
        + "col_tsrange TSRANGE, "
        + "col_tstzrange TSTZRANGE, "
        + "col_daterange DATERANGE) SPLIT INTO 1 TABLETS";

    try (Statement stmt = connection.createStatement()) {
      stmt.execute(create_stmt);
      stmt.execute("CREATE PUBLICATION pub FOR ALL TABLES");
    }

    Connection conn =
        getConnectionBuilder().withTServer(0).replicationConnect();
    PGReplicationConnection replConnection = conn.unwrap(PGConnection.class).getReplicationAPI();

    replConnection.createReplicationSlot()
        .logical()
        .withSlotName("test_slot_repl_conn_all_data_types")
        .withOutputPlugin("pgoutput")
        .make();

    try (Statement stmt = connection.createStatement()) {
      stmt.execute("INSERT INTO test_table VALUES ("
          + "1, B'110110', TRUE, '((0,0),(1,1))', E'\\\\x012345', '127.0.0.1', '((0,0),1)', "
          + "'2024-02-01', 1.201, 3.14, '127.0.0.1', 42, "
          + "'{\"key\": \"value\"}', '{\"key\": \"value\"}', "
          + "'{1,2,3}', '((0,0),(1,1))', '00:11:22:33:44:55:66:77', '00:11:22:33:44:55', 100.50, "
          + "123.456, '((0,0),(1,1))', '(0,0)', '((0,0),(1,1))', 'Sample Text', '12:34:56', "
          + "'2024-02-01 12:34:56', '2024-02-01 12:34:56+00:00', "
          + "'550e8400-e29b-41d4-a716-446655440000', B'101010', '2024-02-01 12:34:56+00:00', "
          + "'[1,10)', '[100,1000)', '[2024-01-01, 2024-12-31)', "
          + "'[2024-01-01 00:00:00+00:00, 2024-12-31 23:59:59+00:00)', "
          + "'[2024-01-01, 2024-12-31)');");
    }

    PGReplicationStream stream = replConnection.replicationStream()
                                     .logical()
                                     .withSlotName("test_slot_repl_conn_all_data_types")
                                     .withStartPosition(LogSequenceNumber.valueOf(0L))
                                     .withSlotOption("proto_version", 1)
                                     .withSlotOption("publication_names", "pub")
                                     .start();

    List<PgOutputMessage> result = new ArrayList<PgOutputMessage>();
    // 1 Relation, begin, insert and commit record.
    result.addAll(receiveMessage(stream, 4));
    for (PgOutputMessage res : result) {
      LOG.info("Row = {}", res);
    }

    List<PgOutputMessage> expectedResult = new ArrayList<PgOutputMessage>() {
      {
        add(PgOutputBeginMessage.CreateForComparison(LogSequenceNumber.valueOf("0/4"), 1));
        add(PgOutputRelationMessage.CreateForComparison("public", "test_table", 'd',
            Arrays.asList(
                PgOutputRelationMessageColumn.CreateForComparison("a", 23),
                PgOutputRelationMessageColumn.CreateForComparison("col_bit", 1560),
                PgOutputRelationMessageColumn.CreateForComparison("col_boolean", 16),
                PgOutputRelationMessageColumn.CreateForComparison("col_box", 603),
                PgOutputRelationMessageColumn.CreateForComparison("col_bytea", 17),
                PgOutputRelationMessageColumn.CreateForComparison("col_cidr", 650),
                PgOutputRelationMessageColumn.CreateForComparison("col_circle", 718),
                PgOutputRelationMessageColumn.CreateForComparison("col_date", 1082),
                PgOutputRelationMessageColumn.CreateForComparison("col_float", 701),
                PgOutputRelationMessageColumn.CreateForComparison("col_double", 701),
                PgOutputRelationMessageColumn.CreateForComparison("col_inet", 869),
                PgOutputRelationMessageColumn.CreateForComparison("col_int", 23),
                PgOutputRelationMessageColumn.CreateForComparison("col_json", 114),
                PgOutputRelationMessageColumn.CreateForComparison("col_jsonb", 3802),
                PgOutputRelationMessageColumn.CreateForComparison("col_line", 628),
                PgOutputRelationMessageColumn.CreateForComparison("col_lseg", 601),
                PgOutputRelationMessageColumn.CreateForComparison("col_macaddr8", 774),
                PgOutputRelationMessageColumn.CreateForComparison("col_macaddr", 829),
                PgOutputRelationMessageColumn.CreateForComparison("col_money", 790),
                PgOutputRelationMessageColumn.CreateForComparison("col_numeric", 1700),
                PgOutputRelationMessageColumn.CreateForComparison("col_path", 602),
                PgOutputRelationMessageColumn.CreateForComparison("col_point", 600),
                PgOutputRelationMessageColumn.CreateForComparison("col_polygon", 604),
                PgOutputRelationMessageColumn.CreateForComparison("col_text", 25),
                PgOutputRelationMessageColumn.CreateForComparison("col_time", 1083),
                PgOutputRelationMessageColumn.CreateForComparison("col_timestamp", 1114),
                PgOutputRelationMessageColumn.CreateForComparison("col_timetz", 1266),
                PgOutputRelationMessageColumn.CreateForComparison("col_uuid", 2950),
                PgOutputRelationMessageColumn.CreateForComparison("col_varbit", 1562),
                PgOutputRelationMessageColumn.CreateForComparison("col_timestamptz", 1184),
                PgOutputRelationMessageColumn.CreateForComparison("col_int4range", 3904),
                PgOutputRelationMessageColumn.CreateForComparison("col_int8range", 3926),
                PgOutputRelationMessageColumn.CreateForComparison("col_tsrange", 3908),
                PgOutputRelationMessageColumn.CreateForComparison("col_tstzrange", 3910),
                PgOutputRelationMessageColumn.CreateForComparison("col_daterange", 3912))));
        add(PgOutputInsertMessage.CreateForComparison(new PgOutputMessageTuple((short) 35,
            Arrays.asList(new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "1"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "110110"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "t"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "(1,1),(0,0)"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "\\x012345"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "127.0.0.1/32"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "<(0,0),1>"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "2024-02-01"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "1.20100000000000007"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "3.14000000000000012"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "127.0.0.1"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "42"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "{\"key\": \"value\"}"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "{\"key\": \"value\"}"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "{1,2,3}"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "[(0,0),(1,1)]"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "00:11:22:33:44:55:66:77"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "00:11:22:33:44:55"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "$100.50"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "123.456"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "((0,0),(1,1))"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "(0,0)"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "((0,0),(1,1))"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "Sample Text"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "12:34:56"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "2024-02-01 12:34:56"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "12:34:56+00"),
                new PgOutputMessageTupleColumn(
                    NOT_NULL, NOT_TOASTED, "550e8400-e29b-41d4-a716-446655440000"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "101010"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "2024-02-01 18:04:56+05:30"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "[1,10)"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "[100,1000)"),
                new PgOutputMessageTupleColumn(
                    NOT_NULL, NOT_TOASTED, "[\"2024-01-01 00:00:00\",\"2024-12-31 00:00:00\")"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED,
                    "[\"2024-01-01 05:30:00+05:30\",\"2025-01-01 05:29:59+05:30\")"),
                new PgOutputMessageTupleColumn(
                    NOT_NULL, NOT_TOASTED, "[2024-01-01,2024-12-31)")))));
        add(PgOutputCommitMessage.CreateForComparison(
            LogSequenceNumber.valueOf("0/4"), LogSequenceNumber.valueOf("0/5")));
=======
        add(PgOutputInsertMessage.CreateForComparison(new PgOutputMessageTuple((short) 2,
=======
        add(PgOutputInsertMessage.CreateForComparison(new PgOutputMessageTuple((short) 3,
>>>>>>> e61807f685 (Introduce support for update operation)
            Arrays.asList(
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "3"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "hijk"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "f")))));
        add(PgOutputCommitMessage.CreateForComparison(
            LogSequenceNumber.valueOf("0/A"), LogSequenceNumber.valueOf("0/B")));
<<<<<<< HEAD
>>>>>>> 9c106d26b2 (Introduce MVP support to consume changes via ReplicationSlot and Walsender)
=======

        add(PgOutputBeginMessage.CreateForComparison(LogSequenceNumber.valueOf("0/D"), 1));
        add(PgOutputUpdateMessage.CreateForComparison(
            new PgOutputMessageTuple((short) 3,
                Arrays.asList(new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "1"),
                    new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "abcd"),
                    new PgOutputMessageTupleColumn(
                        NOT_NULL, TOASTED, PgOutputMessageDecoder.IGNORED_EMPTY_STRING))),
            new PgOutputMessageTuple((short) 3,
                Arrays.asList(new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "1"),
                    new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "updated_abcd"),
                    new PgOutputMessageTupleColumn(
                        NOT_NULL, TOASTED, PgOutputMessageDecoder.IGNORED_EMPTY_STRING)))));
        add(PgOutputCommitMessage.CreateForComparison(
            LogSequenceNumber.valueOf("0/D"), LogSequenceNumber.valueOf("0/E")));

        add(PgOutputBeginMessage.CreateForComparison(LogSequenceNumber.valueOf("0/10"), 1));
        add(PgOutputUpdateMessage.CreateForComparison(
            new PgOutputMessageTuple((short) 3,
                Arrays.asList(new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "2"),
                    new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "defg"),
                    new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "t"))),
            new PgOutputMessageTuple((short) 3,
                Arrays.asList(new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "2"),
                    new PgOutputMessageTupleColumn(
                        NULL, NOT_TOASTED, PgOutputMessageDecoder.IGNORED_EMPTY_STRING),
                    new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "f")))));
        add(PgOutputCommitMessage.CreateForComparison(
            LogSequenceNumber.valueOf("0/10"), LogSequenceNumber.valueOf("0/11")));
>>>>>>> e61807f685 (Introduce support for update operation)
      }
    };
    assertEquals(expectedResult, result);

    stream.close();
  }

  @Test
  public void replicationConnectionConsumptionAllDataTypes() throws Exception {
    String create_stmt = "CREATE TABLE test_table ( "
        + "a INT PRIMARY KEY, "
        + "col_bit BIT(6), "
        + "col_boolean BOOLEAN, "
        + "col_box BOX, "
        + "col_bytea BYTEA, "
        + "col_cidr CIDR, "
        + "col_circle CIRCLE, "
        + "col_date DATE, "
        + "col_float FLOAT, "
        + "col_double DOUBLE PRECISION, "
        + "col_inet INET, "
        + "col_int INT, "
        + "col_json JSON, "
        + "col_jsonb JSONB, "
        + "col_line LINE, "
        + "col_lseg LSEG, "
        + "col_macaddr8 MACADDR8, "
        + "col_macaddr MACADDR, "
        + "col_money MONEY, "
        + "col_numeric NUMERIC, "
        + "col_path PATH, "
        + "col_point POINT, "
        + "col_polygon POLYGON, "
        + "col_text TEXT, "
        + "col_time TIME, "
        + "col_timestamp TIMESTAMP, "
        + "col_timetz TIMETZ, "
        + "col_uuid UUID, "
        + "col_varbit VARBIT(10), "
        + "col_timestamptz TIMESTAMPTZ, "
        + "col_int4range INT4RANGE, "
        + "col_int8range INT8RANGE, "
        + "col_tsrange TSRANGE, "
        + "col_tstzrange TSTZRANGE, "
        + "col_daterange DATERANGE) SPLIT INTO 1 TABLETS";

    try (Statement stmt = connection.createStatement()) {
      stmt.execute(create_stmt);
      stmt.execute("CREATE PUBLICATION pub FOR ALL TABLES");
    }

    Connection conn =
        getConnectionBuilder().withTServer(0).replicationConnect();
    PGReplicationConnection replConnection = conn.unwrap(PGConnection.class).getReplicationAPI();

    replConnection.createReplicationSlot()
        .logical()
        .withSlotName("test_slot_repl_conn_all_data_types")
        .withOutputPlugin("pgoutput")
        .make();

    try (Statement stmt = connection.createStatement()) {
      stmt.execute("INSERT INTO test_table VALUES ("
          + "1, B'110110', TRUE, '((0,0),(1,1))', E'\\\\x012345', '127.0.0.1', '((0,0),1)', "
          + "'2024-02-01', 1.201, 3.14, '127.0.0.1', 42, "
          + "'{\"key\": \"value\"}', '{\"key\": \"value\"}', "
          + "'{1,2,3}', '((0,0),(1,1))', '00:11:22:33:44:55:66:77', '00:11:22:33:44:55', 100.50, "
          + "123.456, '((0,0),(1,1))', '(0,0)', '((0,0),(1,1))', 'Sample Text', '12:34:56', "
          + "'2024-02-01 12:34:56', '2024-02-01 12:34:56+00:00', "
          + "'550e8400-e29b-41d4-a716-446655440000', B'101010', '2024-02-01 12:34:56+00:00', "
          + "'[1,10)', '[100,1000)', '[2024-01-01, 2024-12-31)', "
          + "'[2024-01-01 00:00:00+00:00, 2024-12-31 23:59:59+00:00)', "
          + "'[2024-01-01, 2024-12-31)');");
    }

    PGReplicationStream stream = replConnection.replicationStream()
                                     .logical()
                                     .withSlotName("test_slot_repl_conn_all_data_types")
                                     .withStartPosition(LogSequenceNumber.valueOf(0L))
                                     .withSlotOption("proto_version", 1)
                                     .withSlotOption("publication_names", "pub")
                                     .start();

    List<PgOutputMessage> result = new ArrayList<PgOutputMessage>();
    // 1 Relation, begin, insert and commit record.
    result.addAll(receiveMessage(stream, 4));
    for (PgOutputMessage res : result) {
      LOG.info("Row = {}", res);
    }

    List<PgOutputMessage> expectedResult = new ArrayList<PgOutputMessage>() {
      {
        add(PgOutputBeginMessage.CreateForComparison(LogSequenceNumber.valueOf("0/4"), 1));
        add(PgOutputRelationMessage.CreateForComparison("public", "test_table", 'd',
            Arrays.asList(
                PgOutputRelationMessageColumn.CreateForComparison("a", 23),
                PgOutputRelationMessageColumn.CreateForComparison("col_bit", 1560),
                PgOutputRelationMessageColumn.CreateForComparison("col_boolean", 16),
                PgOutputRelationMessageColumn.CreateForComparison("col_box", 603),
                PgOutputRelationMessageColumn.CreateForComparison("col_bytea", 17),
                PgOutputRelationMessageColumn.CreateForComparison("col_cidr", 650),
                PgOutputRelationMessageColumn.CreateForComparison("col_circle", 718),
                PgOutputRelationMessageColumn.CreateForComparison("col_date", 1082),
                PgOutputRelationMessageColumn.CreateForComparison("col_float", 701),
                PgOutputRelationMessageColumn.CreateForComparison("col_double", 701),
                PgOutputRelationMessageColumn.CreateForComparison("col_inet", 869),
                PgOutputRelationMessageColumn.CreateForComparison("col_int", 23),
                PgOutputRelationMessageColumn.CreateForComparison("col_json", 114),
                PgOutputRelationMessageColumn.CreateForComparison("col_jsonb", 3802),
                PgOutputRelationMessageColumn.CreateForComparison("col_line", 628),
                PgOutputRelationMessageColumn.CreateForComparison("col_lseg", 601),
                PgOutputRelationMessageColumn.CreateForComparison("col_macaddr8", 774),
                PgOutputRelationMessageColumn.CreateForComparison("col_macaddr", 829),
                PgOutputRelationMessageColumn.CreateForComparison("col_money", 790),
                PgOutputRelationMessageColumn.CreateForComparison("col_numeric", 1700),
                PgOutputRelationMessageColumn.CreateForComparison("col_path", 602),
                PgOutputRelationMessageColumn.CreateForComparison("col_point", 600),
                PgOutputRelationMessageColumn.CreateForComparison("col_polygon", 604),
                PgOutputRelationMessageColumn.CreateForComparison("col_text", 25),
                PgOutputRelationMessageColumn.CreateForComparison("col_time", 1083),
                PgOutputRelationMessageColumn.CreateForComparison("col_timestamp", 1114),
                PgOutputRelationMessageColumn.CreateForComparison("col_timetz", 1266),
                PgOutputRelationMessageColumn.CreateForComparison("col_uuid", 2950),
                PgOutputRelationMessageColumn.CreateForComparison("col_varbit", 1562),
                PgOutputRelationMessageColumn.CreateForComparison("col_timestamptz", 1184),
                PgOutputRelationMessageColumn.CreateForComparison("col_int4range", 3904),
                PgOutputRelationMessageColumn.CreateForComparison("col_int8range", 3926),
                PgOutputRelationMessageColumn.CreateForComparison("col_tsrange", 3908),
                PgOutputRelationMessageColumn.CreateForComparison("col_tstzrange", 3910),
                PgOutputRelationMessageColumn.CreateForComparison("col_daterange", 3912))));
        add(PgOutputInsertMessage.CreateForComparison(new PgOutputMessageTuple((short) 35,
            Arrays.asList(new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "1"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "110110"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "t"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "(1,1),(0,0)"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "\\x012345"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "127.0.0.1/32"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "<(0,0),1>"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "2024-02-01"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "1.20100000000000007"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "3.14000000000000012"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "127.0.0.1"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "42"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "{\"key\": \"value\"}"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "{\"key\": \"value\"}"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "{1,2,3}"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "[(0,0),(1,1)]"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "00:11:22:33:44:55:66:77"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "00:11:22:33:44:55"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "$100.50"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "123.456"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "((0,0),(1,1))"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "(0,0)"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "((0,0),(1,1))"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "Sample Text"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "12:34:56"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "2024-02-01 12:34:56"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "12:34:56+00"),
                new PgOutputMessageTupleColumn(
                    NOT_NULL, NOT_TOASTED, "550e8400-e29b-41d4-a716-446655440000"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "101010"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "2024-02-01 18:04:56+05:30"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "[1,10)"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "[100,1000)"),
                new PgOutputMessageTupleColumn(
                    NOT_NULL, NOT_TOASTED, "[\"2024-01-01 00:00:00\",\"2024-12-31 00:00:00\")"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED,
                    "[\"2024-01-01 05:30:00+05:30\",\"2025-01-01 05:29:59+05:30\")"),
                new PgOutputMessageTupleColumn(
                    NOT_NULL, NOT_TOASTED, "[2024-01-01,2024-12-31)")))));
        add(PgOutputCommitMessage.CreateForComparison(
            LogSequenceNumber.valueOf("0/4"), LogSequenceNumber.valueOf("0/5")));
      }
    };
    assertEquals(expectedResult, result);

    stream.close();
  }

  @Test
  public void replicationConnectionConsumptionDisabled() throws Exception {
    markClusterNeedsRecreation();
    Map<String, String> tserverFlags = super.getTServerFlags();
    tserverFlags.put("ysql_TEST_enable_replication_slot_consumption", "false");
    restartClusterWithFlags(Collections.emptyMap(), tserverFlags);

    try (Statement stmt = connection.createStatement()) {
      stmt.execute("CREATE TABLE t1 (a int primary key, b text) SPLIT INTO 1 TABLETS");
      stmt.execute("CREATE PUBLICATION pub FOR ALL TABLES");
    }

    Connection conn =
        getConnectionBuilder().withTServer(0).replicationConnect();
    PGReplicationConnection replConnection = conn.unwrap(PGConnection.class).getReplicationAPI();

    replConnection.createReplicationSlot()
        .logical()
        .withSlotName("test_slot_repl_conn_disabled")
        .withOutputPlugin("pgoutput")
        .make();

    String expectedErrorMessage = "ERROR: StartReplication is unavailable";

    boolean exceptionThrown = false;
    try {
      replConnection.replicationStream()
          .logical()
          .withSlotName("test_slot_repl_conn_disabled")
          .withStartPosition(LogSequenceNumber.valueOf(0L))
          .withSlotOption("proto_version", 1)
          .withSlotOption("publication_names", "pub")
          .start();
    } catch (PSQLException e) {
      exceptionThrown = true;
      if (StringUtils.containsIgnoreCase(e.getMessage(), expectedErrorMessage)) {
        LOG.info("Expected exception", e);
      } else {
        fail(String.format("Unexpected Error Message. Got: '%s', Expected to contain: '%s'",
            e.getMessage(), expectedErrorMessage));
      }
    }

    assertTrue("Expected an exception but wasn't thrown", exceptionThrown);
  }

  // TODO(#20726): Add a test case which verifies that operations with #changes > batch_size works
  // fine. This should be done once we have moved to using the `GetConsistentChanges` RPC.
}
