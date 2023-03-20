// Copyright (c) YugaByte, Inc.
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

#include "yb/util/pg_util.h"

#include <algorithm>
#include <string>

#include <glog/logging.h>

#include "yb/util/format.h"
#include "yb/util/hash_util.h"
#include "yb/util/flags/flag_tags.h"

DECLARE_string(yb_tmp_path);

namespace yb {

// Derive a socket directory name for tserver-postgres authentication purposes.
// The directory should be unique to each tserver (and its postgres) running on the same machine.
// Accomplish this by putting the bind address host and port in the directory name.  To avoid the
// 107 character limit for the socket path (see UNIXSOCK_PATH_BUFLEN - 1 in postgres fe-connect.c),
// truncate and use a hash of the bind address if needed.
std::string PgDeriveSocketDir(const HostPort& host_port) {
  const std::string& host = host_port.host();
  const uint16_t port = host_port.port();

  constexpr size_t kSocketMaxChars = 107;
  // Port (16-bit) int can only be at most 5 digits long.
  constexpr size_t kDefaultSocketDirLen = 8;
  constexpr auto defaultSocketDirPrefix = "/tmp/.yb";
  std::string prefix = defaultSocketDirPrefix;
  size_t kPrefixChars = kDefaultSocketDirLen;
  // Hash (64-bit) uint can only be at most 20 digits long, plus minimum 1 character from host.
  constexpr size_t kMinHostCharsWithHash = 21;
  // directory name: 1 dot, 1 pound, 1 colon; 1 slash separating socket dir and socket file.
  constexpr size_t kMaxSeparatorCharWithHash = 4;

  constexpr size_t kPortMaxChars = 5;
  DCHECK_LE(std::to_string(port).size(), kPortMaxChars);
  // ".s.PGSQL.<port>" = 9 chars + max 5 chars
  constexpr size_t kSocketFileChars = 14;
  DCHECK_EQ(strlen(".s.PGSQL.") + kPortMaxChars, kSocketFileChars);
  // directory name: 1 dot, 1 colon; 1 slash separating socket dir and socket file.
  constexpr size_t kSeparatorChars = 3;

  if (!FLAGS_yb_tmp_path.empty()) {
    if (FLAGS_yb_tmp_path.size() + strlen("/.yb") <=
        (kSocketMaxChars -
         (kPortMaxChars + kMaxSeparatorCharWithHash + kSocketFileChars + kMinHostCharsWithHash))) {
      prefix = FLAGS_yb_tmp_path + "/.yb";
      kPrefixChars = FLAGS_yb_tmp_path.size() + strlen("/.yb");
    } else {
      LOG(WARNING) << "Failed to use path " << FLAGS_yb_tmp_path
                   << " to create socket path for tserver-Postgres authentication purpose, which "
                   << "exceeds the character limit for the socket path defined in Postgres, so "
                   << "go with the default /tmp path.";
    }
  }

  constexpr size_t kDefaultHostMaxChars = 77;
  size_t kHostMaxChars = kDefaultHostMaxChars;
  // If default /tmp path is used to create the unix-domain socket.
  if (prefix == defaultSocketDirPrefix) {
    DCHECK_EQ(prefix.size(), kPrefixChars);
    DCHECK_EQ(
        kSocketMaxChars - (kPrefixChars + kPortMaxChars + kSeparatorChars + kSocketFileChars),
        kHostMaxChars);
  } else {
    kHostMaxChars =
        kSocketMaxChars - (kPrefixChars + kPortMaxChars + kSeparatorChars + kSocketFileChars);
  }

  // Make socket directory path.
  std::string path;
  if (host.size() <= kHostMaxChars) {
    // Normal case: "/tmp/.yb.<host>:<port>".
    path = Format("$0.$1:$2", prefix, host, port);
  } else {
    // Special case when host address is too long: "/tmp/.yb.<truncated_host>#<host_hash>:<port>".
    const uint64_t hash = HashUtil::MurmurHash2_64(host.c_str(), host.size(), 0 /* seed */);
    // Hash (64-bit) uint can only be at most 20 digits long.
    constexpr size_t kHashMaxChars = 20;
    DCHECK_LE(std::to_string(hash).size(), kHashMaxChars);
    // directory name: 1 dot, 1 pound, 1 colon; 1 slash separating socket dir and socket file.
    constexpr size_t kSeparatorChars = 4;
    constexpr size_t kLongHostMaxChars = 56;
    size_t kHostMaxChars = kLongHostMaxChars;
    // If default /tmp path is used to create the unix-domain socket.
    if (kPrefixChars == kDefaultSocketDirLen) {
      DCHECK_EQ(
          kSocketMaxChars -
              (kPrefixChars + kHashMaxChars + kPortMaxChars + kSeparatorChars + kSocketFileChars),
          kHostMaxChars);
    } else {
      kHostMaxChars = kSocketMaxChars - (kPrefixChars + kHashMaxChars + kPortMaxChars +
                                         kSeparatorChars + kSocketFileChars);
    }
    const std::string& host_substring = host.substr(0, kHostMaxChars);
    path = Format("$0.$1#$2:$3", prefix, host_substring, hash, port);
  }
  DCHECK_LE(path.size(), kSocketMaxChars);
  return path;
}

} // namespace yb
