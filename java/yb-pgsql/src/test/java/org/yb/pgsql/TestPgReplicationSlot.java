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
import org.yb.pgsql.PgOutputMessageDecoder.PgOutputBeginMessage;
import org.yb.pgsql.PgOutputMessageDecoder.PgOutputCommitMessage;
import org.yb.pgsql.PgOutputMessageDecoder.PgOutputInsertMessage;
import org.yb.pgsql.PgOutputMessageDecoder.PgOutputMessage;
import org.yb.pgsql.PgOutputMessageDecoder.PgOutputMessageTuple;
import org.yb.pgsql.PgOutputMessageDecoder.PgOutputMessageTupleColumn;
import org.yb.pgsql.PgOutputMessageDecoder.PgOutputRelationMessage;
import org.yb.pgsql.PgOutputMessageDecoder.PgOutputRelationMessageColumn;

import com.yugabyte.PGConnection;
import com.yugabyte.replication.LogSequenceNumber;
import com.yugabyte.replication.PGReplicationConnection;
import com.yugabyte.replication.PGReplicationStream;
import com.yugabyte.util.PSQLException;

@RunWith(value = YBTestRunner.class)
public class TestPgReplicationSlot extends BasePgSQLTest {
  private static final Logger LOG = LoggerFactory.getLogger(TestPgReplicationSlot.class);
  private static final boolean NOT_NULL = false;
  private static final boolean NOT_TOASTED = false;

  @Override
  protected int getInitialNumTServers() {
    return 3;
  }

  @Override
  protected Map<String, String> getTServerFlags() {
    Map<String, String> flagMap = super.getTServerFlags();
    flagMap.put("allowed_preview_flags_csv", "ysql_yb_enable_replication_commands");
    flagMap.put("ysql_yb_enable_replication_commands", "true");
    flagMap.put("ysql_TEST_enable_replication_slot_consumption", "true");
    flagMap.put("vmodule", "cdc_service=4,cdcsdk_producer=4");
    return flagMap;
  }

  @Override
  protected Map<String, String> getMasterFlags() {
    Map<String, String> flagMap = super.getMasterFlags();
    flagMap.put("allowed_preview_flags_csv", "ysql_yb_enable_replication_commands");
    flagMap.put("ysql_yb_enable_replication_commands", "true");
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
        .withOutputPlugin("yboutput")
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
          .withOutputPlugin("yboutput")
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

  @Test
  public void replicationConnectionConsumption() throws Exception {
    try (Statement stmt = connection.createStatement()) {
      stmt.execute("CREATE TABLE t1 (a int primary key, b text) SPLIT INTO 1 TABLETS");
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
      stmt.execute("INSERT INTO t1 VALUES(1, 'abcd')");
      stmt.execute("INSERT INTO t1 VALUES(2, 'defg')");
      stmt.execute("INSERT INTO t1 VALUES(3, 'hijk')");
    }

    PGReplicationStream stream = replConnection.replicationStream()
                                     .logical()
                                     .withSlotName("test_slot_repl_conn")
                                     .withStartPosition(LogSequenceNumber.valueOf(0L))
                                     .withSlotOption("proto_version", 1)
                                     .withSlotOption("publication_names", "pub")
                                     .start();

    List<PgOutputMessage> result = new ArrayList<PgOutputMessage>();
    // 1 Relation, 3 * 3 (begin, insert and commit).
    result.addAll(receiveMessage(stream, 10));
    for (PgOutputMessage res : result) {
      LOG.info("Row = {}", res);
    }

    List<PgOutputMessage> expectedResult = new ArrayList<PgOutputMessage>() {
      {
        add(PgOutputBeginMessage.CreateForComparison(LogSequenceNumber.valueOf("0/4"), 1));
        add(PgOutputRelationMessage.CreateForComparison("public", "t1", 'd',
            Arrays.asList(PgOutputRelationMessageColumn.CreateForComparison("a", 23),
                PgOutputRelationMessageColumn.CreateForComparison("b", 25))));
        add(PgOutputInsertMessage.CreateForComparison(new PgOutputMessageTuple((short) 2,
            Arrays.asList(
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "1"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "abcd")))));
        add(PgOutputCommitMessage.CreateForComparison(
            LogSequenceNumber.valueOf("0/4"), LogSequenceNumber.valueOf("0/5")));

        add(PgOutputBeginMessage.CreateForComparison(LogSequenceNumber.valueOf("0/7"), 1));
        add(PgOutputInsertMessage.CreateForComparison(new PgOutputMessageTuple((short) 2,
            Arrays.asList(
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "2"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "defg")))));
        add(PgOutputCommitMessage.CreateForComparison(
            LogSequenceNumber.valueOf("0/7"), LogSequenceNumber.valueOf("0/8")));

        add(PgOutputBeginMessage.CreateForComparison(LogSequenceNumber.valueOf("0/A"), 1));
        add(PgOutputInsertMessage.CreateForComparison(new PgOutputMessageTuple((short) 2,
            Arrays.asList(
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "3"),
                new PgOutputMessageTupleColumn(NOT_NULL, NOT_TOASTED, "hijk")))));
        add(PgOutputCommitMessage.CreateForComparison(
            LogSequenceNumber.valueOf("0/A"), LogSequenceNumber.valueOf("0/B")));
      }
    };
    assertEquals(expectedResult, result);

    stream.close();
  }

  @Test
  public void replicationConnectionConsumptionDisabled() throws Exception {
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
}
