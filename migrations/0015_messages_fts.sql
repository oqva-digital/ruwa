-- Full-text search over message bodies, BM25-ranked.
--
-- External-content FTS5 index mirrors messages.body_text keyed by the base
-- table's implicit rowid; triggers keep it in sync on insert/update/delete.
-- `unicode61 remove_diacritics 2` makes search case- and accent-insensitive
-- (so "jose" matches "José"), which matters for the largely-Portuguese corpus.
-- Replaces the previous `body_text LIKE '%needle%'` substring scan.

CREATE VIRTUAL TABLE messages_fts USING fts5(
    body_text,
    content='messages',
    content_rowid='rowid',
    tokenize='unicode61 remove_diacritics 2'
);

-- Backfill the index from rows that already exist. NULL bodies index as the
-- empty document, which is harmless (they simply never match a query).
INSERT INTO messages_fts (rowid, body_text)
    SELECT rowid, body_text FROM messages;

CREATE TRIGGER messages_fts_ai AFTER INSERT ON messages BEGIN
    INSERT INTO messages_fts (rowid, body_text) VALUES (new.rowid, new.body_text);
END;

CREATE TRIGGER messages_fts_ad AFTER DELETE ON messages BEGIN
    INSERT INTO messages_fts (messages_fts, rowid, body_text)
        VALUES ('delete', old.rowid, old.body_text);
END;

CREATE TRIGGER messages_fts_au AFTER UPDATE ON messages BEGIN
    INSERT INTO messages_fts (messages_fts, rowid, body_text)
        VALUES ('delete', old.rowid, old.body_text);
    INSERT INTO messages_fts (rowid, body_text) VALUES (new.rowid, new.body_text);
END;
