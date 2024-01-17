/*--------------------------------------------------------------------------------------------------
 *
 * yb_virtual_wal.c
 *        Commands for readings records from the YB WAL
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
 *        src/postgres/src/backend/replication/logical/yb_virtual_wal.c
 *
 *--------------------------------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/xlog_internal.h"
#include "commands/ybccmds.h"
#include "replication/logical.h"
#include "replication/slot.h"
#include "replication/yb_lsn_gen.h"
#include "replication/yb_virtual_wal.h"
#include "utils/memutils.h"

// TODO: Do we need this? Should this only be for the tablet checkpoint but not
// for record batch?
static MemoryContext virtual_wal_context = NULL;
static List *tablet_checkpoints = NIL;

static YBCPgChangeRecordBatch *record_batch = NULL;
static size_t record_batch_last_sent_row_idx = 0;

static void YBCGetTabletCheckpoints(List *tables);
static void YBCSetInitialTabletCheckpoints();
static YBCPgVirtualWalRecord *
YBCPrepareVirtualWalRecord(LogicalDecodingContext *ctx, XLogReaderState *state,
						   XLogRecPtr record_lsn);

void
YBCInitVirtualWal(List *tables)
{
	MemoryContext caller_context;

	virtual_wal_context = AllocSetContextCreate(GetCurrentMemoryContext(),
												"YB virtual WAL context",
												ALLOCSET_DEFAULT_SIZES);
	caller_context = MemoryContextSwitchTo(virtual_wal_context);

	YBCInitLSNGen();
	YBCGetTabletCheckpoints(tables);
	YBCSetInitialTabletCheckpoints();

	MemoryContextSwitchTo(caller_context);
}

void
YBCDestroyVirtualWal()
{
	YBCDestroyLSNGen();

	if (virtual_wal_context != NULL)
		MemoryContextDelete(virtual_wal_context);
}

static void
YBCGetTabletCheckpoints(List *tables)
{
	YBC_LOG_INFO("Getting all tablets to poll");

    // TODO: free the previous checkpoint if already present.
	tablet_checkpoints = NIL;

	ListCell *lc;
	foreach (lc, tables)
	{
		YBCPgTabletCheckpoint *checkpoints;
		size_t numtablets;

		YBCGetTabletListToPollForStreamAndTable(
			MyReplicationSlot->data.yb_stream_id, lfirst_oid(lc), &checkpoints,
			&numtablets);

		YBC_LOG_INFO("Got %zu tablets for table: %u", numtablets,
					 lfirst_oid(lc));

		for (size_t i = 0; i < numtablets; i++)
			tablet_checkpoints = lappend(tablet_checkpoints, &checkpoints[i]);
	}

	YBC_LOG_INFO("The number of tablet checkpoints after storing them = %d",
				 list_length(tablet_checkpoints));
}

static void
YBCSetInitialTabletCheckpoints()
{
	YBC_LOG_INFO("Setting initial checkpoints for all tablets");

	ListCell *lc;
	foreach (lc, tablet_checkpoints)
	{
		YBCPgTabletCheckpoint *tc = (YBCPgTabletCheckpoint *) lfirst(lc);
		YBCPgCDCSDKCheckpoint *new_checkpoint;

		new_checkpoint = palloc(sizeof(YBCPgCDCSDKCheckpoint));
		new_checkpoint->index = 0;
		new_checkpoint->term = 0;

		YBC_LOG_INFO("Time to make the YBCSetCDCTabletCheckpoint call.");
		YBCSetCDCTabletCheckpoint(MyReplicationSlot->data.yb_stream_id,
								  tc->location->tablet_id, new_checkpoint, 0,
								  true);

		tc->checkpoint->index = 0;
		tc->checkpoint->term = 0;
	}
}

YBCPgVirtualWalRecord *
YBCReadRecord(LogicalDecodingContext *ctx, XLogReaderState *state,
			  XLogRecPtr RecPtr, char **errormsg)
{
	MemoryContext			caller_context;
	XLogRecPtr				record_lsn = InvalidXLogRecPtr;
	YBCPgVirtualWalRecord	*record = NULL;

	caller_context = MemoryContextSwitchTo(virtual_wal_context);

	YBC_LOG_INFO("YBCReadRecord start with tablet_checkpoints != NIL: %d, "
				 "number of tablet checkpoints = %d",
				 tablet_checkpoints != NIL, list_length(tablet_checkpoints));

	/* reset error state */
	*errormsg = NULL;
	state->errormsg_buf[0] = '\0';

	YBC_LOG_INFO("Going to reset decoder");

	YBResetDecoder(state);

	YBC_LOG_INFO("Done resetting decoder");

	/* Fetch a batch of changes from CDC service if needed. */
	if (record_batch == NULL ||
		record_batch_last_sent_row_idx >= record_batch->row_count)
	{
		YBC_LOG_INFO("Getting fresh batch of changes");

		ListCell *lc;
		foreach (lc, tablet_checkpoints)
		{
			YBCPgTabletCheckpoint *tc = (YBCPgTabletCheckpoint *) lfirst(lc);

			/* TODO: Free record_batch if not null. */

			YBC_LOG_INFO("Time to make the YBCGetCDCChanges call.");
			YBCGetCDCChanges(MyReplicationSlot->data.yb_stream_id,
							 tc->location->tablet_id, tc->checkpoint,
							 &record_batch);

			YBC_LOG_INFO("Got response from YBCGetCDCChanges.");
			if (tc->checkpoint)
				pfree(tc->checkpoint);

			YBC_LOG_INFO("Updated checkpoint from response is: term = %lld, "
						 "index = %lld",
						 record_batch->checkpoint->term,
						 record_batch->checkpoint->index);
			/* TODO: If we got no records, consider setting wal sender caught up
			 * to true. */
			tc->checkpoint = record_batch->checkpoint;
		}

		record_batch_last_sent_row_idx = 0;
	}

	Assert(record_batch);

	/* Get an LSN from the generator. */
	record_lsn = YBCGenerateLSN();

	/* Prepare the YBCPgVirtualWalRecord from the row. */
	record = YBCPrepareVirtualWalRecord(ctx, state, record_lsn);

	state->yb_virtual_wal_record = (struct YBCPgVirtualWalRecord *) record;

	MemoryContextSwitchTo(caller_context);
	return record;
}

static YBCPgVirtualWalRecord *
YBCPrepareVirtualWalRecord(LogicalDecodingContext *ctx, XLogReaderState *state,
						   XLogRecPtr record_lsn)
{
	YBCPgRowMessage			*row = NULL;
	YBCPgVirtualWalRecord	*record = palloc(sizeof(YBCPgVirtualWalRecord));

	YBC_LOG_INFO("YBCPrepareVirtualWalRecord with record_lsn = %lu, "
				 "record_batch_last_sent_row_idx = %zu",
				 record_lsn, record_batch_last_sent_row_idx);

	row = &record_batch->rows[record_batch_last_sent_row_idx];
	record_batch_last_sent_row_idx++;

	YBC_LOG_INFO("YBCPrepareVirtualWalRecord row->action = %u, ", row->action);
	switch (row->action)
	{
		case YB_PG_ROW_MESSAGE_ACTION_UNKNOWN: switch_fallthrough();
		case YB_PG_ROW_MESSAGE_ACTION_BEGIN:
			/* Ignore the UNKNOWN/BEGIN message. */
			return YBCPrepareVirtualWalRecord(ctx, state, record_lsn);

		case YB_PG_ROW_MESSAGE_ACTION_COMMIT:
		{
			record->type = YB_VIRTUAL_WAL_RECORD_TYPE_COMMIT;
			record->val.commit = palloc(sizeof(YBCPgVirtualWalCommitRecord));
			/* TODO: Populate correct transaction id. */
			record->xid = 1;
			break;
		}
		case YB_PG_ROW_MESSAGE_ACTION_INSERT:
		{
			record->type = YB_VIRTUAL_WAL_RECORD_TYPE_CHANGE;
			record->val.change = ReorderBufferGetChange(ctx->reorder);

			record->val.change->lsn = record_lsn;
			record->val.change->action = REORDER_BUFFER_CHANGE_INSERT;
			record->xid = 1;

			state->ReadRecPtr = record_lsn;
			break;
		}
		case YB_PG_ROW_MESSAGE_ACTION_UPDATE:
		{
			record->type = YB_VIRTUAL_WAL_RECORD_TYPE_CHANGE;
			record->val.change = ReorderBufferGetChange(ctx->reorder);

			record->val.change->lsn = record_lsn;
			record->val.change->action = REORDER_BUFFER_CHANGE_UPDATE;
			record->xid = 1;

			state->ReadRecPtr = record_lsn;
			break;
		}
		case YB_PG_ROW_MESSAGE_ACTION_DELETE:
		{
			record->type = YB_VIRTUAL_WAL_RECORD_TYPE_CHANGE;
			record->val.change = ReorderBufferGetChange(ctx->reorder);

			record->val.change->lsn = record_lsn;
			record->val.change->action = REORDER_BUFFER_CHANGE_DELETE;
			record->xid = 1;

			state->ReadRecPtr = record_lsn;
			break;
		}
	}

	return record;
}

XLogRecPtr
YBCGetFlushRecPtr(void)
{
	return InvalidXLogRecPtr;
}
