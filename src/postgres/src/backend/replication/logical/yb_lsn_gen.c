/*--------------------------------------------------------------------------------------------------
 *
 * yb_lsn_gen.c
 *        Commands for generating a Log Sequence Number for the virtual WAL.
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
 *        src/postgres/src/backend/replication/logical/yb_lsn_gen.c
 *
 *--------------------------------------------------------------------------------------------------
 */

#include "postgres.h"

#include "commands/ybccmds.h"

/* The LSN of the last record streamed via logical replication. */
static XLogRecPtr yb_last_lsn = InvalidXLogRecPtr;

void
YBCInitLSNGen()
{
	yb_last_lsn = InvalidXLogRecPtr;
}

void
YBCDestroyLSNGen()
{

}

XLogRecPtr
YBCGenerateLSN()
{
	return ++yb_last_lsn;
}
