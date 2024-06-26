//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under the BSD-style license found in the
//  LICENSE file in the root directory of this source tree. An additional grant
//  of patent rights can be found in the PATENTS file in the same directory.
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
#pragma once

#include <string.h>

#include "yb/rocksdb/env.h"
#include "yb/rocksdb/statistics.h"

namespace rocksdb {
// Auto-scoped.
// Records the measure time into the corresponding histogram if statistics
// is not nullptr. It is also saved into *elapsed if the pointer is not nullptr.
class StopWatch {
 public:
  StopWatch(Env * const env, Statistics* statistics,
            const uint32_t hist_type,
            uint64_t* elapsed = nullptr)
    : env_(env),
      statistics_(statistics),
      hist_type_(hist_type),
      elapsed_(elapsed),
      stats_enabled_(statistics && statistics->HistEnabledForType(hist_type)),
      start_time_((stats_enabled_ || elapsed != nullptr) ?
                  env->NowMicros() : 0) {
  }


  ~StopWatch() {
    if (elapsed_) {
      *elapsed_ = env_->NowMicros() - start_time_;
    }
    if (stats_enabled_) {
      statistics_->measureTime(hist_type_,
          (elapsed_ != nullptr) ? *elapsed_ :
                                  (env_->NowMicros() - start_time_));
    }
  }

 private:
  Env* const env_;
  Statistics* statistics_;
  const uint32_t hist_type_;
  uint64_t* elapsed_;
  bool stats_enabled_;
  const uint64_t start_time_;
};

// a nano second precision stopwatch
class StopWatchNano {
 public:
  explicit StopWatchNano(Env* const env, bool auto_start = false)
      : env_(env), start_(0) {
    if (auto_start) {
      Start();
    }
  }

  void Start() { start_ = env_->NowNanos(); }

  uint64_t ElapsedNanos(bool reset = false) {
    auto now = env_->NowNanos();
    auto elapsed = now - start_;
    if (reset) {
      start_ = now;
    }
    return elapsed;
  }

  uint64_t ElapsedNanosSafe(bool reset = false) {
    return (env_ != nullptr) ? ElapsedNanos(reset) : 0U;
  }

 private:
  Env* const env_;
  uint64_t start_;
};

} // namespace rocksdb
