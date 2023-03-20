// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
//
// The following only applies to changes made to this file as part of YugaByte development.
//
// Portions Copyright (c) YugaByte, Inc.
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
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <iosfwd>
#include <string>
#include <type_traits>

#include <glog/logging.h>
#include <gtest/gtest.h>

#include "yb/gutil/hash/hash.h"
#include "yb/gutil/integral_types.h"
#include "yb/gutil/port.h"
#include "yb/gutil/type_traits.h"
#include "yb/util/format.h"
#include "yb/util/hash_util.h"
#include "yb/util/net/net_util.h"
#include "yb/util/pg_util.h"

DECLARE_string(yb_tmp_path);

namespace yb {

// Test Murmur2 Hash64 returns the expected values for inputs. These tests are
// duplicated on the Java side to ensure that hash computations are stable
// across both platforms.
TEST(HashUtilTest, TestMurmur2Hash64) {
  uint64_t hash;

  hash = HashUtil::MurmurHash2_64("ab", 2, 0);
  ASSERT_EQ(7115271465109541368, hash);

  hash = HashUtil::MurmurHash2_64("abcdefg", 7, 0);
  ASSERT_EQ(2601573339036254301, hash);

  hash = HashUtil::MurmurHash2_64("quick brown fox", 15, 42);
  ASSERT_EQ(3575930248840144026, hash);
}

TEST(HashUtilTest, PgSocketDerivation) {
  LOG(INFO) << "Test IP addresses";
  ASSERT_EQ("/tmp/.yb.127.0.0.1:5433", PgDeriveSocketDir(HostPort("127.0.0.1", 5433)));
  ASSERT_EQ("/tmp/.yb.127.255.255.254:65535",
            PgDeriveSocketDir(HostPort("127.255.255.254", 65535)));

  LOG(INFO) << "Test names";
  constexpr auto kHostPrefix = "aaaaaaaaa.bbbbbbbbb.ccccccccc.ddddddddd.eeeeeeeee";
  constexpr auto kPort = 18008;
  // 63-char name
  ASSERT_EQ(
      Format("/tmp/.yb.$0.fffffffff.ggg:$1", kHostPrefix, kPort),
      PgDeriveSocketDir(HostPort(Format("$0.fffffffff.ggg", kHostPrefix), kPort)));
  // 64-char name
  ASSERT_EQ(
      Format("/tmp/.yb.$0.fffffffff.gggg:$1", kHostPrefix, kPort),
      PgDeriveSocketDir(HostPort(Format("$0.fffffffff.gggg", kHostPrefix), kPort)));
  // 77-char name
  ASSERT_EQ(
      Format("/tmp/.yb.$0.fffffffff.ggggggggg.hhhhhhh:$1", kHostPrefix, kPort),
      PgDeriveSocketDir(HostPort(Format("$0.fffffffff.ggggggggg.hhhhhhh", kHostPrefix), kPort)));
  // 78-char name
  ASSERT_EQ(
      Format("/tmp/.yb.$0.ffffff#9194157326238941401:$1", kHostPrefix, kPort),
      PgDeriveSocketDir(HostPort(Format("$0.fffffffff.ggggggggg.hhhhhhhh", kHostPrefix), kPort)));
  // 99-char name
  ASSERT_EQ(
      Format("/tmp/.yb.$0.ffffff#17919586771964798778:$1", kHostPrefix, kPort),
      PgDeriveSocketDir(HostPort(Format("$0.fffffffff.ggggggggg.hhhhhhhhh.iiiiiiiii.jjjjjjjjj",
                                        kHostPrefix),
                                 kPort)));
  // 255-char name
  ASSERT_EQ(
      Format("/tmp/.yb.$0.ffffff#10320903717037216904:$1", kHostPrefix, kPort),
      PgDeriveSocketDir(HostPort(Format("$0.fffffffff.ggggggggg.hhhhhhhhh.iiiiiiiii.jjjjjjjjj."
                                        "kkkkkkkkk.lllllllll.mmmmmmmmm.nnnnnnnnn.ooooooooo."
                                        "ppppppppp.qqqqqqqqq.rrrrrrrrr.sssssssss.ttttttttt."
                                        "uuuuuuuuu.vvvvvvvvv.wwwwwwwww.xxxxxxxxx.yyyyyyyyy.zzzzz",
                                        kHostPrefix),
                                 kPort)));
}

TEST(HashUtilTest, PgSocketDerivationWithCustomisePath) {
  FLAGS_yb_tmp_path = "/aaaaa/bbb/ccc";
  constexpr auto port = 65535;
  // Here flag as well as hostname is smaller than 107 character limit for the socket path.
  ASSERT_EQ(
      Format("$0/.yb.127.0.0.1:$1", FLAGS_yb_tmp_path, port),
      PgDeriveSocketDir(HostPort("127.0.0.1", port)));

  constexpr auto hostname_prefix = "aaaaaaaaa.bbbbbbbbb.ccccccccc.ddddddddd.eeeeeeeee";

  // Verify the scenario with a smaller custom path with the largest hostname without trimming.
  std::string largest_hostname = Format("$0.$1", hostname_prefix, "fffffffff.ggggggg");
  ASSERT_EQ(
      PgDeriveSocketDir(HostPort(largest_hostname, port)),
      Format("$0/.yb.$1:$2", FLAGS_yb_tmp_path, largest_hostname, port));

  // Verify the scenario with the smaller custom path with the largest host +1(host trimming).
  std::string trim_hostname = Format("$0$1", largest_hostname, "g");
  ASSERT_EQ(
      PgDeriveSocketDir(HostPort(trim_hostname, port)),
      Format(
          "$0/.yb.aaaaaaaaa.bbbbbbbbb.ccccccccc.ddddddddd.eeeeee#6684209500661080486:$1",
          FLAGS_yb_tmp_path,
          port));

  // Verify the scenario with a larger custom path without trimming with the largest hostname
  // without trimming.
  FLAGS_yb_tmp_path = "/aaaaaaaaaaaa/bbbbbbbbbbbb/ccccccccccc/dddddddddd/eeeeeeeee";
  largest_hostname = "aaaaaaaaa.bbbbbbbbb.cc";
  ASSERT_EQ(
      PgDeriveSocketDir(HostPort(largest_hostname, port)),
      Format("$0/.yb.$1:$2", FLAGS_yb_tmp_path, largest_hostname, port));

  // Verify the scenario with a larger custom path without trimming with largest hostname + 1 with
  // trimming.
  FLAGS_yb_tmp_path = "/aaaaaaaaaaaa/bbbbbbbbbbbb/ccccccccccc/dddddddddd/eeeeeeeee";
  trim_hostname = Format("$0$1", largest_hostname, "g");
  ASSERT_EQ(
      PgDeriveSocketDir(HostPort(trim_hostname, port)),
      Format("$0/.yb.a#13331612183759290547:$2", FLAGS_yb_tmp_path, largest_hostname, port));

  // Verify the scenario with a larger custom path with trimming with the largest hostname without
  // trimming.
  FLAGS_yb_tmp_path =
      "/aaaaaaaaaaaa/bbbbbbbbbbbb/ccccccccccc/dddddddddd/eeeeeeeee/ggg/hhhhhhhhhh/kkkkkkkkk/"
      "pppppppppppppp/kkkkkkkkkkkkk/kkkkkkkkkkkkkkkkkkkkkk/ppppppppp";
  largest_hostname = Format("$0.$1", hostname_prefix, "fffffffff.ggggggg");
  ASSERT_EQ(
      PgDeriveSocketDir(HostPort(largest_hostname, port)),
      Format("/tmp/.yb.$1:$2", FLAGS_yb_tmp_path, largest_hostname, port));

  // Verify the scenario with a larger custom path with trimming with the largest hostname with
  // trimming.
  trim_hostname = Format("$0.$1", largest_hostname, "hhhhhhhh.iiiiii");
  ASSERT_EQ(
      PgDeriveSocketDir(HostPort(trim_hostname, port)),
      Format(
          "/tmp/"
          ".yb.aaaaaaaaa.bbbbbbbbb.ccccccccc.ddddddddd.eeeeeeeee.ffffff#9465513402506384780:$1",
          largest_hostname,
          port));
}

} // namespace yb
