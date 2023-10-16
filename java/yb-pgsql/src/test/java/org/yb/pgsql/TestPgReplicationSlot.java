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

import java.sql.Connection;
import java.sql.Statement;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yb.YBTestRunner;

import com.yugabyte.PGConnection;
import com.yugabyte.replication.PGReplicationConnection;

@RunWith(value = YBTestRunner.class)
public class TestPgReplicationSlot extends BasePgSQLTest {
    private static final Logger LOG = LoggerFactory.getLogger(TestPgReplicationSlot.class);

  @Override
  protected int getInitialNumTServers() {
    return 3;
  }

  /** Restart cluster with specified hba conf. */
  private void restartWithHba(String hba) throws Exception {
    Map<String, String> flagMap = super.getTServerFlags();

    // ysql_enable_auth auto-adds an HBA entry, so turn it off.
    flagMap.put("ysql_enable_auth", "false");

    // Add given hba.
    flagMap.put("ysql_hba_conf_csv", hba);
    LOG.info("Restarting with the following HBA config: {}", flagMap.get("ysql_hba_conf_csv"));

    restartClusterWithFlags(Collections.emptyMap(), flagMap);
  }

  @Test
  public void createAndDropFromDifferentTservers() throws Exception {
    Connection conn1 = getConnectionBuilder().withTServer(0).connect();
    Connection conn2 = getConnectionBuilder().withTServer(1).connect();

    try (Statement statement = conn1.createStatement()) {
      statement.execute("select pg_create_logical_replication_slot('test_slot', 'yboutput')");
    }
    try (Statement statement = conn2.createStatement()) {
      statement.execute("select pg_drop_replication_slot('test_slot')");
    }
    try (Statement statement = conn1.createStatement()) {
      statement.execute("select pg_create_logical_replication_slot('test_slot', 'yboutput')");
    }
    try (Statement statement = conn2.createStatement()) {
      statement.execute("select pg_drop_replication_slot('test_slot')");
    }
  }

  @Test
  public void createAndDropViaReplicationConnection() throws Exception {
    restartWithHba(String.format("host all all 0.0.0.0/0 trust"));

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
}
