/*-------------------------------------------------------------------------
 *
 * pg_yb_publication_meta.h
 *	  definition of the system catalog for mapping between publication and
 *	  CDC stream (pg_yb_publication_meta)
 *
 *
 * Copyright (c) YugaByte, Inc.
 *
 * src/include/catalog/pg_yb_publication_meta.h
 *
 * NOTES
 *	  The Catalog.pm module reads this file and derives schema
 *	  information.
 *
 *-------------------------------------------------------------------------
 */
#ifndef PG_YB_PUBLICATION_META_H
#define PG_YB_PUBLICATION_META_H

#include "catalog/genbki.h"
#include "catalog/pg_yb_publication_meta_d.h"

/* ----------------
 *		pg_yb_publication_meta definition.  cpp turns this into
 *		typedef struct FormData_pg_yb_publication_meta
 * ----------------
 */
CATALOG(pg_yb_publication_meta,8065,YbPublicationMetaRelationId)
{
	Oid			prpubid;				/* Oid of the publication */
	varchar(32)			prstrid;		/* Oid of the stream */
} FormData_pg_yb_publication_meta;

/* ----------------
 *		Form_pg_yb_publication_meta corresponds to a pointer to a tuple with
 *		the format of pg_yb_publication_meta relation.
 * ----------------
 */
typedef FormData_pg_yb_publication_meta *Form_pg_yb_publication_meta;

#endif							/* PG_YB_PUBLICATION_META_H */
