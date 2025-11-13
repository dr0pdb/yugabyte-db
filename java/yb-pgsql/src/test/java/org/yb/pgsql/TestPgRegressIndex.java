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

import java.util.Collections;
import java.util.Map;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yb.util.YBTestRunnerNonTsanOnly;

// Runs the pg_regress test suite on YB code.
@RunWith(value=YBTestRunnerNonTsanOnly.class)
public class TestPgRegressIndex extends BasePgRegressTest {
  private static final Logger LOG = LoggerFactory.getLogger(TestPgRegressIndex.class);

  @Override
  public int getTestMethodTimeoutSec() {
    return 1800;
  }

  @Override
  protected Map<String, String> getTServerFlags() {
    Map<String, String> flagMap = super.getTServerFlags();
    // TODO (#19975): Enable read committed isolation
    flagMap.put("yb_enable_read_committed_isolation", "false");
    // Disable auto analyze because it aborts the SQL snippet:
    // force_cache_refresh which increments catalog version explictly.
    flagMap.put("ysql_enable_auto_analyze", "false");
    flagMap.put("ysql_yb_ddl_transaction_block_enabled", "true");
    flagMap.put("enable_object_locking_for_table_locks", "false");
    return flagMap;
  }

  @Test
  public void schedule() throws Exception {
    // (DB-13032) This test touches system tables, so enable stickiness for
    // superuser connections when Connection Manager is enabled.
    enableStickySuperuserConnsAndRestartCluster();
    runPgRegressTest("yb_index_schedule");
  }

  // TODO(#29344): Remove once Txn ddl is enabled by default in all builds.
  @Test
  public void scheduleWithoutTxnDdl() throws Exception {
    // (DB-13032) This test touches system tables, so enable stickiness for
    // superuser connections when Connection Manager is enabled.
    if (isTestRunningWithConnectionManager()) {
      ysql_conn_mgr_superuser_sticky = true;
    }
    Map<String, String> tserverFlagMap = getTServerFlags();
    tserverFlagMap.put("ysql_yb_ddl_transaction_block_enabled", "false");
    restartClusterWithFlags(super.getMasterFlags(), tserverFlagMap);
    runPgRegressTest("yb_index_without_txn_ddl_schedule");
  }
}
