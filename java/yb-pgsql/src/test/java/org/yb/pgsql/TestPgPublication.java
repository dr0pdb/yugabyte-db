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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.sql.ResultSet;
import java.sql.Statement;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yb.YBTestRunner;

@RunWith(value = YBTestRunner.class)
public class TestPgPublication extends BasePgSQLTest {
  private static final Logger LOG = LoggerFactory.getLogger(TestPgPublication.class);

  @Test
  public void basicTest() throws Exception {
    createSimpleTable("test");
    try (Statement statement = connection.createStatement()) {
      LOG.info("Creating publication...");
      statement.execute("CREATE PUBLICATION test_publication FOR ALL TABLES");
      LOG.info("Done creating publication...");

      LOG.info("Query pg_publication");
      try (ResultSet rs = statement.executeQuery("SELECT * FROM pg_publication")) {
        assertNextRow(rs, "test_publication", 16384L, true, true, true, true, true);
        assertFalse(rs.next());
      }

      // Only populated if we specify list of tables.
      // LOG.info("Query pg_publication_rel");
      // try (ResultSet rs = statement.executeQuery("SELECT * FROM pg_publication_rel")) {
      //   assertTrue(rs.next());
      //   Row actual = Row.fromResultSet(rs);
      //   LOG.info(String.format("Received row = %s", actual));
      //   assertFalse(rs.next());
      // }

      LOG.info("Query pg_yb_publication_meta");
      try (ResultSet rs = statement.executeQuery("SELECT * FROM pg_yb_publication_meta")) {
        assertTrue(rs.next());
        Row actual = Row.fromResultSet(rs);
        LOG.info("Received row = %s", actual);
        assertFalse(rs.next());
      }
    }
  }
}
