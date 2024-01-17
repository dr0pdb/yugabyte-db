/*--------------------------------------------------------------------------------------------------
 *
 * yb_decode.c
 *		This module decodes YB Virtual WAL records read using yb_virtual_wal.h's APIs for the
 *		purpose of logical decoding by passing information to the
 *		reorderbuffer module (containing the actual changes).
 *
 * Copyright (c) YugaByte, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied.  See the License for the specific language governing permissions and limitations
 * under the License.
 *
 * IDENTIFICATION
 *        src/postgres/src/backend/replication/logical/yb_decode.c
 *
 *--------------------------------------------------------------------------------------------------
 */

#include "postgres.h"
#include "replication/yb_decode.h"
#include "replication/yb_virtual_wal.h"

void
YBLogicalDecodingProcessRecord(LogicalDecodingContext *ctx,
							   XLogReaderState *record)
{
	YBC_LOG_INFO("YBLogicalDecodingProcessRecord start");

	YBCPgVirtualWalRecord *yb_record =
		(YBCPgVirtualWalRecord *) record->yb_virtual_wal_record;

	YBC_LOG_INFO("YBLogicalDecodingProcessRecord txnid: %d", yb_record->xid);

	switch (yb_record->type)
	{
		case YB_VIRTUAL_WAL_RECORD_TYPE_COMMIT:
		{
			break;
		}
		case YB_VIRTUAL_WAL_RECORD_TYPE_CHANGE:
		{
			ReorderBufferChange *change = yb_record->val.change;
			ReorderBufferProcessXid(ctx->reorder, yb_record->xid,
									ctx->reader->ReadRecPtr);
			ReorderBufferQueueChange(ctx->reorder, yb_record->xid,
									 ctx->reader->ReadRecPtr, change);
			break;
		}
	}
}
