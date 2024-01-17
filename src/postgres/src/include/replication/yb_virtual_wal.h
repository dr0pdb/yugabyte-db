/*--------------------------------------------------------------------------------------------------
 *
 * yb_virtual_wal.h
 *	  prototypes for yb_virtual_wal.c.
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
 * src/include/replication/yb_virtual_wal.h
 *
 *--------------------------------------------------------------------------------------------------
 */

#ifndef YB_VIRTUAL_WAL_H
#define YB_VIRTUAL_WAL_H

#include "access/xlogreader.h"
#include "c.h"
#include "nodes/pg_list.h"
#include "replication/logical.h"

// Virtual WAL DS -> reorderbuffer
// xlogreader -> Virtual WAL DS
//
// YBReorderBufferChange

typedef enum PgVirtualWalRecordType {
  YB_VIRTUAL_WAL_RECORD_TYPE_COMMIT = 0,
  YB_VIRTUAL_WAL_RECORD_TYPE_CHANGE = 1,
} YBCPgVirtualWalRecordType;

typedef struct PgVirtualWalCommitRecord {
} YBCPgVirtualWalCommitRecord;

typedef union PgVirtualWalRecordValUnion
{
  YBCPgVirtualWalCommitRecord *commit;
  ReorderBufferChange *change;
} YBCPgVirtualWalRecordValUnion;

typedef struct PgVirtualWalRecord
{
  YBCPgVirtualWalRecordType type;
  YBCPgVirtualWalRecordValUnion val;
  TransactionId xid;
} YBCPgVirtualWalRecord;

extern void YBCInitVirtualWal(List *tables);
extern void YBCDestroyVirtualWal();

extern YBCPgVirtualWalRecord *YBCReadRecord(LogicalDecodingContext *ctx,
                                            XLogReaderState *state,
                                            XLogRecPtr RecPtr,
                                            char **errormsg);
extern XLogRecPtr YBCGetFlushRecPtr(void);

#endif
