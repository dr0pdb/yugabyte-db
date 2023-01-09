//--------------------------------------------------------------------------------------------------
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
//--------------------------------------------------------------------------------------------------

#pragma once

#include <list>
#include "yb/common/common_fwd.h"

#include "yb/util/memory/arena.h"
#include "yb/util/memory/arena_fwd.h"
#include "yb/util/status_fwd.h"

#include "yb/yql/pggate/pg_gate_fwd.h"
#include "yb/yql/pggate/ybc_pg_typedefs.h"

namespace yb {
namespace pggate {

// constexpr int POOL_SIZE = 10000;

class FixedObjectPool {
 public:
  // FixedObjectPool() : arena_(SharedArena()), free_() {}

  FixedObjectPool() : free_() {
    id_ = ++next_id;
  }

  PgsqlWriteOpPtr Alloc(
      std::shared_ptr<ThreadSafeArena> arena, bool need_transaction, bool is_region_local) {
    instance_inuse_++;
    if (free_.empty()) {
      total_instances_++;
      LOG(INFO) << __func__ << "::" << getpid() << ": " << id_
                << ": allocating new object. Pool state: " << ToString();
      return ArenaMakeShared<PgsqlWriteOp>(arena, arena.get(), this, need_transaction, is_region_local);
    }

    auto obj = free_.back();
    free_.pop_back();
    LOG(INFO) << __func__ << "::" << getpid() << ": " << id_
              << ": using an existing object. Pool state: " << ToString();
    return obj;
  }

  void DeAlloc(PgsqlWriteOpPtr obj) {
    instance_inuse_--;
    free_.emplace_back(obj);
    LOG(INFO) << __func__ << "::" << getpid() << ": " << id_ << ": Pool state: " << ToString();
  }

  std::string ToString() {
    return Format(
        "FixedObjectPool: id=$0, instance_inuse=$1, free_ size=$2, total_instances=$3", id_, instance_inuse_,
        free_.size(), total_instances_);
  }

  static inline int next_id = 0;

 private:
  // std::shared_ptr<ThreadSafeArena> arena_;

  int instance_inuse_ = 0;
  int total_instances_ = 0;
  int id_;
  std::vector<PgsqlWriteOpPtr> free_;
};

}  // namespace pggate
}  // namespace yb
