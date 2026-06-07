-- Purge protocol fan-out rows that were wrongly persisted as visible chat
-- messages. `history_sync_notification` and `app_state_sync_key_share` are
-- own-account protocol messages (their real side effects — history chunk
-- download, app-state key storage — happen at receive time); they are not chat
-- content and were polluting the self-chat with "sync notif" rows. The inbound
-- path no longer stores them going forward; this clears the backlog.
DELETE FROM messages
WHERE msg_type IN ('history_sync_notification', 'app_state_sync_key_share');
