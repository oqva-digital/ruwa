-- Account NCT ("non-contact token") salt, delivered in the HistorySync blob.
-- Used to derive the <cstoken> = HMAC-SHA256(nct_salt, recipient_lid) that modern
-- WhatsApp requires on 1:1 messages; without it recipients silently drop them.
ALTER TABLE sessions ADD COLUMN nct_salt BLOB;
