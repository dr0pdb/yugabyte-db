BEGIN;
  CREATE TABLE IF NOT EXISTS pg_catalog.pg_yb_publication_meta (
    prpubid oid NOT NULL,
    prstrid oid NOT NULL,
    CONSTRAINT pg_yb_publication_meta_oid_index PRIMARY KEY(oid ASC)
        WITH (table_oid = 8066),
    CONSTRAINT pg_yb_publication_meta_prstrid_index UNIQUE (prstrid)
        WITH (table_oid = 8067)
    CONSTRAINT pg_yb_publication_meta_prpubid_index UNIQUE (prpubid)
        WITH (table_oid = 8068)
  ) WITH (
    oids = true,
    table_oid = 8065,
    row_type_oid = 8069
  ) TABLESPACE pg_global;

COMMIT;
