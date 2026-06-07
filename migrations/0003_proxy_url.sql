-- Per-session egress proxy for the Noise WebSocket (and media via reqwest).
-- Format: socks5://[user:pass@]host:port | socks5h://… | http://[user:pass@]host:port
-- NULL = direct connection (no proxy).
ALTER TABLE sessions ADD COLUMN proxy_url TEXT;
