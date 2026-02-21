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

#include "yb/util/backoff_waiter.h"
#include "yb/yql/pgwrapper/pg_mini_test_base.h"

DECLARE_bool(ysql_yb_enable_colocated_dml_fast_path_optimization);
DECLARE_double(TEST_transaction_ignore_applying_probability);
DECLARE_string(vmodule);
DECLARE_string(ysql_log_statement);

namespace yb {
namespace pgwrapper {

constexpr bool kEmptyIntentsExpected = true;
constexpr bool kNonEmptyIntentsExpected = false;
const MonoDelta kIntentsCleanupTime = 6s * kTimeMultiplier;

class PgDmlSingleShardTxnTest : public PgMiniTestBase {
 public:
  void SetUp() override {
    PgMiniTestBase::SetUp();
    ANNOTATE_UNPROTECTED_WRITE(FLAGS_ysql_yb_enable_colocated_dml_fast_path_optimization) = true;
    ANNOTATE_UNPROTECTED_WRITE(FLAGS_TEST_transaction_ignore_applying_probability) = 1.0;
    ANNOTATE_UNPROTECTED_WRITE(FLAGS_ysql_log_statement) = "all";
    ANNOTATE_UNPROTECTED_WRITE(FLAGS_vmodule) = "pg_session=2,pg_txn_manager=2";
  }

  void ExecuteStmtAndCountIntents(
      const std::function<void()>& stmt_executor, bool zero_intent_count_expected) {
    stmt_executor();

    if (zero_intent_count_expected)
      ASSERT_EQ(CountIntents(cluster_.get()), 0);
    else
      ASSERT_NE(CountIntents(cluster_.get()), 0);
  }

  Status WaitIntentsCleaned() {
    SetAtomicFlag(0, &FLAGS_TEST_transaction_ignore_applying_probability);
    RETURN_NOT_OK(cluster_->FlushTablets());
    RETURN_NOT_OK(WaitFor(
      [this] { return CountIntents(cluster_.get()) == 0; }, kIntentsCleanupTime, "Intents cleaned"));
    SetAtomicFlag(1.0, &FLAGS_TEST_transaction_ignore_applying_probability);
    return Status::OK();
  }
};

TEST_F(PgDmlSingleShardTxnTest, TestFastPathForColocatedInserts) {
  const std::string kDatabaseName = "testdb";
  std::string table_name = "test";

  PGConn conn = ASSERT_RESULT(Connect());
  ASSERT_OK(conn.ExecuteFormat("CREATE DATABASE $0 with colocated=true", kDatabaseName));

  conn = ASSERT_RESULT(ConnectToDB(kDatabaseName));
  ASSERT_OK(
      conn.Execute("CREATE TABLE test (key INT PRIMARY KEY, value1 INT, value2 INT, value3 INT)"));
  ASSERT_OK(conn.Execute("CREATE INDEX test_index_value1 on test(value1)"));
  ASSERT_OK(conn.Execute("CREATE UNIQUE INDEX test_index_value2 on test(value2)"));
  ASSERT_OK(conn.Execute("CREATE INDEX test_index_value3 on test(value3)"));

  // First insert will also read the catalog tables, so it won't go through the fast path.
  ExecuteStmtAndCountIntents(
      [&conn, table_name] {
        ASSERT_OK(conn.ExecuteFormat("INSERT INTO $0 VALUES(1, 1, 1, 1)", table_name));
      },
      kNonEmptyIntentsExpected);
  ASSERT_OK(WaitIntentsCleaned());
  // Now that the catalog tables are cached, the next insert should go through the fast path and
  // leave no intents.
  ExecuteStmtAndCountIntents(
    [&conn, table_name] {
      ASSERT_OK(conn.ExecuteFormat("INSERT INTO $0 VALUES(2, 2, 2, 2)", table_name));
    },
    kEmptyIntentsExpected);

  // Batched statements should not go through the fast path.
  ExecuteStmtAndCountIntents(
    [&conn, table_name] {
      ASSERT_OK(conn.ExecuteFormat(
          "INSERT INTO $0 VALUES(3, 3, 3, 3); INSERT INTO $0 VALUES(4, 4, 4, 4)", table_name));
    },
    kNonEmptyIntentsExpected);
  ASSERT_OK(WaitIntentsCleaned());

  // Disabling fast path should work.
  ASSERT_OK(conn.Execute("SET yb_enable_colocated_dml_fast_path_optimization TO FALSE"));
  ExecuteStmtAndCountIntents(
    [&conn, table_name] {
      ASSERT_OK(conn.ExecuteFormat("INSERT INTO $0 VALUES(5, 5, 5, 5)", table_name));
    },
    kNonEmptyIntentsExpected);
}

TEST_F(PgDmlSingleShardTxnTest, NoFastPathForExplicitTransactionBlock) {
  const std::string kDatabaseName = "testdb";
  const std::string table_name = "test";

  PGConn conn = ASSERT_RESULT(Connect());
  ASSERT_OK(conn.ExecuteFormat("CREATE DATABASE $0 with colocated=true", kDatabaseName));
  conn = ASSERT_RESULT(ConnectToDB(kDatabaseName));
  ASSERT_OK(conn.Execute(
      "CREATE TABLE test (key INT PRIMARY KEY, value1 INT, value2 INT, value3 INT)"));

  ExecuteStmtAndCountIntents(
      [&conn, table_name] {
        ASSERT_OK(conn.ExecuteFormat(
            "BEGIN; INSERT INTO $0 VALUES(1, 1, 1, 1); COMMIT;", table_name));
      },
      kNonEmptyIntentsExpected);
}

} // namespace pgwrapper
} // namespace yb
