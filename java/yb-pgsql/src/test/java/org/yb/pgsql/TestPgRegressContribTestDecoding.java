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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.yb.client.TestUtils;
import org.yb.YBTestRunner;

import java.io.File;
import java.util.Map;

@RunWith(value=YBTestRunner.class)
public class TestPgRegressContribTestDecoding extends BasePgRegressTest {
  private static int kPublicationRefreshIntervalSec = 5;

  @Override
  public int getTestMethodTimeoutSec() {
    return 1800;
  }

  @Override
  protected Map<String, String> getTServerFlags() {
    Map<String, String> flagMap = super.getTServerFlags();

    if (isTestRunningWithConnectionManager()) {
      String preview_flags = "ysql_yb_enable_replication_commands," +
        "yb_enable_cdc_consistent_snapshot_streams,enable_ysql_conn_mgr," +
        "ysql_yb_enable_replica_identity,cdcsdk_enable_dynamic_table_support";
      flagMap.put("allowed_preview_flags_csv",preview_flags);
      flagMap.put("ysql_conn_mgr_stats_interval", "1");
    } else {
      flagMap.put("allowed_preview_flags_csv",
          "ysql_yb_enable_replication_commands," +
          "yb_enable_cdc_consistent_snapshot_streams," +
          "ysql_yb_enable_replica_identity," +
          "cdcsdk_enable_dynamic_table_support");
    }
    flagMap.put("ysql_yb_enable_replication_commands", "true");
    flagMap.put("yb_enable_cdc_consistent_snapshot_streams", "true");
    flagMap.put("ysql_TEST_enable_replication_slot_consumption", "true");
    flagMap.put("ysql_yb_enable_replica_identity", "true");
    flagMap.put("vmodule", "ybc_pggate=4,cdcsdk_virtual_wal=4");
    flagMap.put("ysql_log_min_messages", "DEBUG2");
    flagMap.put(
        "cdcsdk_publication_list_refresh_interval_secs","" + kPublicationRefreshIntervalSec);
    flagMap.put("cdcsdk_enable_dynamic_table_support", "true");
    return flagMap;
  }

  @Override
  protected Map<String, String> getMasterFlags() {
    Map<String, String> flagMap = super.getMasterFlags();
    flagMap.put("allowed_preview_flags_csv",
        "ysql_yb_enable_replication_commands," +
        "yb_enable_cdc_consistent_snapshot_streams," +
        "ysql_yb_enable_replica_identity");
    flagMap.put("ysql_yb_enable_replication_commands", "true");
    flagMap.put("yb_enable_cdc_consistent_snapshot_streams", "true");
    flagMap.put("ysql_TEST_enable_replication_slot_consumption", "true");
    flagMap.put("ysql_yb_enable_replica_identity", "true");
    return flagMap;
  }

  @Test
  public void schedule() throws Exception {
    runPgRegressTest(new File(TestUtils.getBuildRootDir(), "postgres_build/contrib/test_decoding"),
                     "yb_schedule");
  }
}
