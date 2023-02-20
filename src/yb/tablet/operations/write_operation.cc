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

#include "yb/tablet/operations/write_operation.h"

#include "yb/consensus/consensus.messages.h"

#include "yb/tablet/tablet.h"
#include "yb/tablet/transaction_participant.h"

#include "yb/util/debug-util.h"
#include "yb/util/debug/trace_event.h"
#include "yb/util/flags.h"
#include "yb/util/trace.h"

DEFINE_test_flag(int32, tablet_inject_latency_on_apply_write_txn_ms, 0,
                 "How much latency to inject when a write operation is applied.");
DEFINE_test_flag(bool, tablet_pause_apply_write_ops, false,
                 "Pause applying of write operations.");

namespace yb {
namespace tablet {

template <>
void RequestTraits<LWWritePB>::SetAllocatedRequest(
    consensus::LWReplicateMsg* replicate, LWWritePB* request) {
  replicate->ref_write(request);
}

template <>
LWWritePB* RequestTraits<LWWritePB>::MutableRequest(consensus::LWReplicateMsg* replicate) {
  return replicate->mutable_write();
}

Status WriteOperation::Prepare(IsLeaderSide is_leader_side) {
  TRACE_EVENT0("txn", "WriteOperation::Prepare");
  return Status::OK();
}

Status WriteOperation::DoAborted(const Status& status) {
  TRACE("FINISH: aborting operation");
  return status;
}

// FIXME: Since this is called as a void in a thread-pool callback,
// it seems pointless to return a Status!
Status WriteOperation::DoReplicated(int64_t leader_term, Status* complete_status) {
  TRACE_EVENT0("txn", "WriteOperation::Complete");
  TRACE("APPLY: Starting");
  LOG(INFO) << __func__ << " for request: " << request()->ShortDebugString();

  auto injected_latency = GetAtomicFlag(&FLAGS_TEST_tablet_inject_latency_on_apply_write_txn_ms);
  if (PREDICT_FALSE(injected_latency) > 0) {
      TRACE("Injecting $0ms of latency due to --TEST_tablet_inject_latency_on_apply_write_txn_ms",
            injected_latency);
      SleepFor(MonoDelta::FromMilliseconds(injected_latency));
  } else {
    TEST_PAUSE_IF_FLAG(TEST_tablet_pause_apply_write_ops);
  }

  *complete_status = VERIFY_RESULT(tablet_safe())->ApplyRowOperations(this);
  // Failure is regular case, since could happen because transaction was aborted, while
  // replicating its intents.
  LOG_IF(INFO, !complete_status->ok()) << "Apply operation failed: " << *complete_status;

  if (operation_mode() == tablet::OperationMode::kSkipIntents && isLeaderSide()) {
  LOG(INFO) << __func__ << " RKNRKN before calling cleanup intents, the operstion mode is "
        << operation_mode() << " is leader side is set to " << isLeaderSide();
    auto tablet = VERIFY_RESULT(tablet_safe());
    auto transaction_participant = tablet->transaction_participant();

    LOG(INFO) << __func__ << " RKNRKN calling cleanup for the transaction with id "
              << TransactionId(transaction_id());

    Status st = transaction_participant->cleanup_intents(TransactionId(transaction_id()));
    if (!st.ok()) {
      LOG(INFO) << __func__ << " RKNRKN the return status of cleanup intents for transaction "
                << TransactionId(transaction_id()) << " is not ok";
      return st;
    }
  }

  // Now that all of the changes have been applied and the commit is durable
  // make the changes visible to readers.
  TRACE("FINISH: making edits visible");

  return Status::OK();
}

HybridTime WriteOperation::WriteHybridTime() const {
  if (request()->has_external_hybrid_time()) {
    return HybridTime(request()->external_hybrid_time());
  }
  return Operation::WriteHybridTime();
}

}  // namespace tablet
}  // namespace yb
