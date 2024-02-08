/*--------------------------------------------------------------------------------------------------
 *
 * yb_decode.c
 *		This module decodes YB Virtual WAL records read using yb_virtual_wal_client.h's APIs for the
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
#include "access/xact.h"
#include "replication/origin.h"
#include "replication/yb_decode.h"
#include "replication/yb_virtual_wal_client.h"
#include "utils/rel.h"

static void
YBDecodeInsert(LogicalDecodingContext *ctx, XLogReaderState *record);
static void
YBDecodeUpdate(LogicalDecodingContext *ctx, XLogReaderState *record);
static void
YBDecodeCommit(LogicalDecodingContext *ctx, XLogReaderState *record);

static int
YBFindAttributeIndexInDescriptor(TupleDesc tupdesc, const char *column_name);

void
YBLogicalDecodingProcessRecord(LogicalDecodingContext *ctx,
							   XLogReaderState *record)
{
	elog(DEBUG4,
		 "YBLogicalDecodingProcessRecord: Decoding record with action = %d.",
		 record->yb_virtual_wal_record->data->action);
	YBC_LOG_INFO("YBLogicalDecodingProcessRecord - %u", record->yb_virtual_wal_record->data->action);
	switch (record->yb_virtual_wal_record->data->action)
	{
		case YB_PG_ROW_MESSAGE_ACTION_UNKNOWN: switch_fallthrough();
		case YB_PG_ROW_MESSAGE_ACTION_DDL:
			/* Ignore UNKNOWN/DDL records. */
			break;

		case YB_PG_ROW_MESSAGE_ACTION_BEGIN:
			/*
			 * Start a transaction so that we can get the relation by oid in
			 * case of change operations. This transaction must be aborted
			 * after processing the corresponding commit record.
			 */
			StartTransactionCommand();
			break;

		case YB_PG_ROW_MESSAGE_ACTION_INSERT:
		{
			YBDecodeInsert(ctx, record);
			break;
		}

		case YB_PG_ROW_MESSAGE_ACTION_UPDATE:
		{
			YBC_LOG_INFO("Update action");
			YBDecodeUpdate(ctx, record);
			break;
		}

		/* TODO(#20726): Support Delete operations. */
		case YB_PG_ROW_MESSAGE_ACTION_DELETE:
			break;

		case YB_PG_ROW_MESSAGE_ACTION_COMMIT:
		{
			YBDecodeCommit(ctx, record);

			/*
			 * Abort the transaction that we started upon receiving the BEGIN
			 * message.
			 */
			AbortCurrentTransaction();
			Assert(!IsTransactionState());
			break;
		}
	}
}

/*
 * YB version of the DecodeInsert function from decode.c
 */
static void
YBDecodeInsert(LogicalDecodingContext *ctx, XLogReaderState *record)
{
	YBCPgVirtualWalRecord	*yb_record = record->yb_virtual_wal_record;
	ReorderBufferChange		*change = ReorderBufferGetChange(ctx->reorder);
	Relation				relation;
	TupleDesc				tupdesc;
	int						nattrs;
	HeapTuple				tuple;
	ReorderBufferTupleBuf	*tuple_buf;

	change->action = REORDER_BUFFER_CHANGE_INSERT;
	change->lsn = yb_record->data->lsn;
	change->origin_id = yb_record->data->lsn;

	ReorderBufferProcessXid(ctx->reorder, yb_record->xid,
							ctx->reader->ReadRecPtr);

	/*
	 * TODO(#20726): This is the schema of the relation at the streaming time.
	 * We need this to be the schema of the table at record commit time.
	 */
	relation = RelationIdGetRelation(yb_record->table_oid);
	if (!RelationIsValid(relation))
		elog(ERROR, "could not open relation with OID %u",
			 yb_record->table_oid);

	tupdesc = RelationGetDescr(relation);
	nattrs = tupdesc->natts;

	Datum datums[nattrs];
	bool is_nulls[nattrs];
	for (int col_idx = 0; col_idx < yb_record->data->col_count; col_idx++)
	{
		YBCPgDatumMessage *col = &yb_record->data->cols[col_idx];

		/*
		 * Column name is null when both new and old values are omitted. This
		 * can only happen in the case of Delete operations.
		 */
		Assert(col->column_name);

		/*
		 * We should always receive all the new columns as part of the Insert
		 * operation.
		 */
		Assert(!col->new_is_omitted);

		int attr_idx =
			YBFindAttributeIndexInDescriptor(tupdesc, col->column_name);
		datums[attr_idx] = col->new_datum;
		is_nulls[attr_idx] = col->new_is_null;
	}
	tuple = heap_form_tuple(tupdesc, datums, is_nulls);

	tuple_buf =
		ReorderBufferGetTupleBuf(ctx->reorder, tuple->t_len + HEAPTUPLESIZE);
	tuple_buf->tuple = *tuple;
	change->data.tp.newtuple = tuple_buf;
	change->data.tp.oldtuple = NULL;
	change->data.tp.yb_table_oid = yb_record->table_oid;

	change->data.tp.clear_toast_afterwards = true;
	ReorderBufferQueueChange(ctx->reorder, yb_record->xid,
							 ctx->reader->ReadRecPtr, change);

	RelationClose(relation);
}

/*
 * YB version of the DecodeUpdate function from decode.c
 */
static void
YBDecodeUpdate(LogicalDecodingContext *ctx, XLogReaderState *record)
{
	YBCPgVirtualWalRecord	*yb_record = record->yb_virtual_wal_record;
	ReorderBufferChange		*change = ReorderBufferGetChange(ctx->reorder);
	Relation				relation;
	TupleDesc				tupdesc;
	int						nattrs;
	HeapTuple				new_tuple;
	HeapTuple				old_tuple;
	ReorderBufferTupleBuf	*new_tuple_buf;
	ReorderBufferTupleBuf	*old_tuple_buf = NULL;
	bool					*old_is_omitted = NULL;
	bool					*new_is_omitted = NULL;

	YBC_LOG_INFO("YBDecodeUpdate");

	change->action = REORDER_BUFFER_CHANGE_UPDATE;
	change->lsn = yb_record->data->lsn;
	change->origin_id = yb_record->data->lsn;

	/*
	 * TODO(#20726): This is the schema of the relation at the streaming time.
	 * We need this to be the schema of the table at record commit time.
	 */
	relation = RelationIdGetRelation(yb_record->table_oid);
	if (!RelationIsValid(relation))
		elog(ERROR, "could not open relation with OID %u",
			 yb_record->table_oid);

	tupdesc = RelationGetDescr(relation);
	nattrs = tupdesc->natts;

	/*
	 * Allocate is_omitted arrays before so that we can directly write to it
	 * instead of creating a temporary array and doing a memcpy.
	 * Assume that columns are omitted by default.
	 */
	old_is_omitted = YBAllocateIsOmittedArray(ctx->reorder, nattrs);
	new_is_omitted = YBAllocateIsOmittedArray(ctx->reorder, nattrs);
	memset(new_is_omitted, 1, sizeof(bool) * nattrs);
	memset(old_is_omitted, 1, sizeof(bool) * nattrs);

	Datum new_datums[nattrs];
	bool new_is_nulls[nattrs];
	Datum old_datums[nattrs];
	bool old_is_nulls[nattrs];
	memset(new_is_nulls, 1, sizeof(new_is_nulls));
	memset(old_is_nulls, 1, sizeof(old_is_nulls));
	for (int col_idx = 0; col_idx < yb_record->data->col_count; col_idx++)
	{
		YBCPgDatumMessage *col = &yb_record->data->cols[col_idx];

		/*
		 * Column name is null when both new and old values are omitted. This
		 * can only happen in the case of Delete operations.
		 */
		Assert(col->column_name);

		int attr_idx =
			YBFindAttributeIndexInDescriptor(tupdesc, col->column_name);

		if (!col->new_is_omitted)
		{
			new_datums[attr_idx] = col->new_datum;
			new_is_nulls[attr_idx] = col->new_is_null;
			new_is_omitted[attr_idx] = false;
		}

		if (!col->old_is_omitted)
		{
			old_datums[attr_idx] = col->old_datum;
			old_is_nulls[attr_idx] = col->old_is_null;
			old_is_omitted[attr_idx] = false;
		}
	}

	new_tuple = heap_form_tuple(tupdesc, new_datums, new_is_nulls);
	new_tuple_buf = ReorderBufferGetTupleBuf(ctx->reorder, new_tuple->t_len + HEAPTUPLESIZE);
	new_tuple_buf->tuple = *new_tuple;
	new_tuple_buf->yb_is_omitted = new_is_omitted;

	old_tuple = heap_form_tuple(tupdesc, old_datums, old_is_nulls);
	old_tuple_buf = ReorderBufferGetTupleBuf(ctx->reorder, old_tuple->t_len + HEAPTUPLESIZE);
	old_tuple_buf->tuple = *old_tuple;
	old_tuple_buf->yb_is_omitted = old_is_omitted;

	change->data.tp.newtuple = new_tuple_buf;
	change->data.tp.oldtuple = old_tuple_buf;
	change->data.tp.yb_table_oid = yb_record->table_oid;

	change->data.tp.clear_toast_afterwards = true;
	ReorderBufferQueueChange(ctx->reorder, yb_record->xid,
							 ctx->reader->ReadRecPtr, change);

	RelationClose(relation);
}

/*
 * YB version of the DecodeCommit function from decode.c
 */
static void
YBDecodeCommit(LogicalDecodingContext *ctx, XLogReaderState *record)
{
	YBCPgVirtualWalRecord	*yb_record = record->yb_virtual_wal_record;
	XLogRecPtr				commit_lsn = yb_record->data->lsn;
	XLogRecPtr				end_lsn = yb_record->data->lsn + 1;
	XLogRecPtr				origin_lsn = yb_record->data->lsn;
	/*
	 * We do not send the replication origin information. So any dummy value is
	 * sufficient here.
	 */
	RepOriginId				origin_id = 1;

	ReorderBufferCommit(ctx->reorder, yb_record->xid, commit_lsn,
						end_lsn, yb_record->data->commit_time, origin_id,
						origin_lsn);
}

/*
 * TODO(#20726): Optimize this lookup via a cache. We do not need to iterate
 * through all attributes everytime this function is called.
 */
static int
YBFindAttributeIndexInDescriptor(TupleDesc tupdesc, const char *column_name)
{
	int attr_idx = 0;
	for (attr_idx = 0; attr_idx < tupdesc->natts; attr_idx++)
	{
		if (!strcmp(tupdesc->attrs[attr_idx].attname.data, column_name))
			break;
	}
	if (attr_idx == tupdesc->natts)
	{
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
					errmsg("Could not find column with name %s in tuple"
						   " descriptor", column_name)));
		return -1;
	}

	return attr_idx;
}
