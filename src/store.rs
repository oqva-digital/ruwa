//! SQLite persistence layer.
//!
//! Backed by an `r2d2` connection pool so concurrent sessions don't serialize
//! on a single connection under WAL (multiple readers + one writer). The
//! `with_conn`/`with_conn_mut` API is unchanged — each call checks a connection
//! out of the pool for the duration of the closure.
//!
//! In-memory stores (`:memory:`, used by tests) use a pool of exactly one
//! connection: a fresh `:memory:` db is private per connection, so a single
//! reused connection is the only way the schema persists across calls. File-
//! backed stores use a real pool (size via `RUWA_DB_POOL_SIZE`, default 8).
//!
//! Schema is managed by `rusqlite_migration` against files in `migrations/`.

use std::path::Path;

use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;
use rusqlite_migration::{Migrations, M};
use serde::{Deserialize, Serialize};

use crate::crypto::vault;

/// Unseal a secret blob read from the store, mapping an at-rest decrypt failure
/// into a `rusqlite` error (from the caller's view, an unreadable secret column
/// is effectively corruption).
fn unseal(blob: Vec<u8>) -> rusqlite::Result<Vec<u8>> {
    vault::open(&blob).map_err(|e| {
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CORRUPT),
            Some(format!("at-rest: {e}")),
        )
    })
}

type Pool = r2d2::Pool<SqliteConnectionManager>;
type PooledConn = r2d2::PooledConnection<SqliteConnectionManager>;

/// Storage backend. Today only SQLite; a `Postgres` variant slots in alongside
/// it without touching call sites (everything goes through the inherent `Store`
/// methods, which dispatch to the active backend). `with_conn`/`with_conn_mut`
/// are SQLite-only raw escape hatches used by tests.
pub enum Store {
    Sqlite(SqliteStore),
    Postgres(PgStore),
}

/// Run a Postgres store call on a fresh OS thread that has no ambient tokio
/// runtime. The sync `postgres` crate drives its connection with its own
/// `Runtime::block_on`, which panics ("cannot start a runtime from within a
/// runtime") when called on a tokio worker thread — which is exactly where every
/// store call runs in the async server. A scoped thread gives a clean context yet
/// can still borrow the (non-`'static`) call arguments; the caller blocks on
/// `join` (same blocking model SQLite already uses). SQLite never goes through
/// here. (Per-call thread spawn is cheap relative to a DB round-trip; the proper
/// async-`tokio-postgres` rewrite is future work.)
fn pg_offload<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    std::thread::scope(|sc| sc.spawn(f).join().unwrap())
}

impl Store {
    /// Open the backend implied by `path`: a `postgres://`/`postgresql://` URL
    /// selects the Postgres backend, anything else is a SQLite path.
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let s = path.as_ref().to_string_lossy();
        if s.starts_with("postgres://") || s.starts_with("postgresql://") {
            Ok(Store::Postgres(pg_offload(|| PgStore::open(&s))?))
        } else {
            Ok(Store::Sqlite(SqliteStore::open(path)?))
        }
    }

    /// Raw SQLite connection access. Panics on a non-SQLite backend — used only
    /// by tests (which always run on SQLite) for direct data seeding/inspection.
    #[allow(dead_code)] // test-only escape hatch
    pub fn with_conn<R>(
        &self,
        f: impl FnOnce(&Connection) -> rusqlite::Result<R>,
    ) -> rusqlite::Result<R> {
        match self {
            Store::Sqlite(s) => s.with_conn(f),
            Store::Postgres(_) => panic!("with_conn is SQLite-only (raw test escape hatch)"),
        }
    }

    #[allow(dead_code)] // test-only escape hatch
    pub fn with_conn_mut<R>(
        &self,
        f: impl FnOnce(&mut Connection) -> rusqlite::Result<R>,
    ) -> rusqlite::Result<R> {
        match self {
            Store::Sqlite(s) => s.with_conn_mut(f),
            Store::Postgres(_) => panic!("with_conn_mut is SQLite-only (raw test escape hatch)"),
        }
    }
}

/// Generate `Store` enum methods that dispatch each domain call to the active
/// backend. One line per method; the body is a `match` over the variants.
macro_rules! store_delegate {
    ( $( $name:ident ( $( $arg:ident : $ty:ty ),* $(,)? ) -> $ret:ty ; )* ) => {
        impl Store {
            $(
                #[allow(clippy::too_many_arguments)]
                pub fn $name(&self $(, $arg : $ty)* ) -> $ret {
                    match self {
                        Store::Sqlite(s) => s.$name( $( $arg ),* ),
                        Store::Postgres(p) => pg_offload(|| p.$name( $( $arg ),* )),
                    }
                }
            )*
        }
    };
}

store_delegate! {
    signal_session_load(session_id: &str, address: &str) -> rusqlite::Result<Option<Vec<u8>>>;
    signal_session_save(session_id: &str, address: &str, record: &[u8], now: i64) -> rusqlite::Result<()>;
    signal_session_delete(session_id: &str, address: &str) -> rusqlite::Result<()>;
    sender_key_load(session_id: &str, group_id: &str, sender: &str) -> rusqlite::Result<Option<Vec<u8>>>;
    sender_key_save(session_id: &str, group_id: &str, sender: &str, record: &[u8]) -> rusqlite::Result<()>;
    lid_pn_put(session_id: &str, lid_user: &str, pn_user: &str, now: i64) -> rusqlite::Result<()>;
    lid_to_pn(session_id: &str, lid_user: &str) -> rusqlite::Result<Option<String>>;
    pn_to_lid(session_id: &str, pn_user: &str) -> rusqlite::Result<Option<String>>;
    message_secret_put(session_id: &str, message_id: &str, chat_jid: &str, sender_jid: &str, secret: &[u8], now: i64) -> rusqlite::Result<()>;
    message_secret_get(session_id: &str, message_id: &str) -> rusqlite::Result<Option<(String, Vec<u8>)>>;
    prekey_count_uploaded(session_id: &str) -> rusqlite::Result<i64>;
    prekeys_pending_upload(session_id: &str, limit: u32) -> rusqlite::Result<Vec<(u32, Vec<u8>)>>;
    prekeys_mark_uploaded(session_id: &str, up_to: u32) -> rusqlite::Result<()>;
    prekey_max_id(session_id: &str) -> rusqlite::Result<u32>;
    prekeys_insert_batch(session_id: &str, batch: &[(u32, &[u8], &[u8])]) -> rusqlite::Result<usize>;
    prekey_load_private(session_id: &str, key_id: u32) -> rusqlite::Result<Option<Vec<u8>>>;
    prekey_delete(session_id: &str, key_id: u32) -> rusqlite::Result<()>;
    message_insert(m: &NewMessage, ignore_conflict: bool) -> rusqlite::Result<()>;
    message_mark_edited(session_id: &str, message_id: &str, new_body: Option<&str>) -> rusqlite::Result<bool>;
    messages_insert_batch(rows: &[NewMessage], ignore_conflict: bool) -> rusqlite::Result<usize>;
    prune(msg_age_cutoff: Option<i64>, messages_per_chat: Option<u32>, signal_age_cutoff: Option<i64>) -> rusqlite::Result<(usize, usize, usize)>;
    message_set_status(session_id: &str, message_id: &str, status: &str) -> rusqlite::Result<()>;
    messages_mark_self_from_me(session_id: &str, own_pn_user: &str, own_lid_user: Option<&str>) -> rusqlite::Result<usize>;
    consolidate_lid_chats(session_id: &str) -> rusqlite::Result<usize>;
    create_session(s: &NewSession, prekeys: &[(u32, &[u8], &[u8])]) -> rusqlite::Result<()>;
    reset_device_keys(r: &DeviceKeyReset, prekeys: &[(u32, &[u8], &[u8])]) -> rusqlite::Result<()>;
    device_keys_load(id: &str) -> rusqlite::Result<Option<DeviceKeyRow>>;
    device_keys_set_adv_secret(id: &str, adv_secret: &[u8]) -> rusqlite::Result<()>;
    sessions_all() -> rusqlite::Result<Vec<SessionRow>>;
    session_delete(id: &str) -> rusqlite::Result<()>;
    session_api_key(id: &str) -> rusqlite::Result<Option<String>>;
    session_set_proxy(id: &str, proxy_url: Option<&str>, updated_at: i64) -> rusqlite::Result<()>;
    session_set_label(id: &str, label: Option<&str>, updated_at: i64) -> rusqlite::Result<()>;
    session_proxy(id: &str) -> rusqlite::Result<Option<String>>;
    session_mark_online(id: &str) -> rusqlite::Result<bool>;
    session_set_mark_online(id: &str, on: bool) -> rusqlite::Result<()>;
    session_account_pb(id: &str) -> rusqlite::Result<Option<Vec<u8>>>;
    session_push_name(id: &str) -> rusqlite::Result<Option<String>>;
    session_set_push_name(id: &str, name: &str) -> rusqlite::Result<()>;
    session_mark_logged_out(id: &str, updated_at: i64) -> rusqlite::Result<()>;
    session_apply_pair_success(id: &str, account_pb: &[u8], biz_name: Option<&str>, platform: Option<&str>, jid: Option<&str>, updated_at: i64) -> rusqlite::Result<()>;
    lease_acquire(session_id: &str, owner: &str, ttl: i64, now: i64) -> rusqlite::Result<bool>;
    lease_renew(session_id: &str, owner: &str, now: i64) -> rusqlite::Result<bool>;
    lease_release(session_id: &str, owner: &str) -> rusqlite::Result<()>;
    lease_holder(session_id: &str, now: i64) -> rusqlite::Result<Option<(String, bool)>>;
    outbound_queue_drain(session_id: &str) -> rusqlite::Result<Vec<String>>;
    outbound_queue_upsert(session_id: &str, msg_id: &str, op_json: &str, created_at: i64) -> rusqlite::Result<()>;
    outbound_queue_delete(session_id: &str, msg_id: &str) -> rusqlite::Result<()>;
    app_state_version_get(session_id: &str, name: &str) -> rusqlite::Result<u64>;
    app_state_hash_get(session_id: &str, name: &str) -> rusqlite::Result<Option<Vec<u8>>>;
    app_state_version_bump(session_id: &str, name: &str, hash: &[u8]) -> rusqlite::Result<()>;
    app_state_version_set(session_id: &str, name: &str, version: u64, hash: &[u8]) -> rusqlite::Result<()>;
    app_state_main_key_save(session_id: &str, key_id: &[u8], key_data: &[u8]) -> rusqlite::Result<()>;
    app_state_main_key_load(session_id: &str, key_id: &[u8]) -> rusqlite::Result<Option<Vec<u8>>>;
    contact_upsert(session_id: &str, jid: &str, full_name: Option<&str>, push_name: Option<&str>) -> rusqlite::Result<()>;
    chat_set_pinned(session_id: &str, jid: &str, pinned: bool) -> rusqlite::Result<()>;
    chat_set_name(session_id: &str, jid: &str, name: Option<&str>, is_group: bool, last_msg_ts: Option<i64>) -> rusqlite::Result<()>;
    chat_set_archived(session_id: &str, jid: &str, archived: bool) -> rusqlite::Result<()>;
    chat_set_muted(session_id: &str, jid: &str, until: Option<i64>) -> rusqlite::Result<()>;
    group_persist(session_id: &str, jid: &str, subject: Option<&str>, creator: Option<&str>, creation_ts: Option<i64>, participants: &[(&str, bool, bool)]) -> rusqlite::Result<()>;
    message_insert_media(session_id: &str, chat_jid: &str, message_id: &str, sender_jid: &str, timestamp: i64, msg_type: &str, body_text: Option<&str>, payload_json: &str, media_path: Option<&str>) -> rusqlite::Result<()>;
    message_set_media_path(session_id: &str, chat_jid: &str, message_id: &str, media_path: &str) -> rusqlite::Result<()>;
    message_media_lookup(session_id: &str, chat_jid: &str, message_id: &str) -> rusqlite::Result<Option<(Option<String>, String, String)>>;
    messages_list(session_id: &str, chat: Option<&str>, needle: Option<&str>, before: i64, limit: u32) -> rusqlite::Result<Vec<MessageListRow>>;
    message_context(session_id: &str, chat: &str, msg_id: &str, before: u32, after: u32) -> rusqlite::Result<Vec<MessageListRow>>;
    message_oldest_for_chat(session_id: &str, chat: &str) -> rusqlite::Result<Option<(String, bool, i64)>>;
    contacts_list(session_id: &str) -> rusqlite::Result<Vec<ContactRow>>;
    chats_list(session_id: &str) -> rusqlite::Result<Vec<ChatRow>>;
    pns_without_lid_mapping(session_id: &str, limit: u32) -> rusqlite::Result<Vec<String>>;
    groups_list(session_id: &str) -> rusqlite::Result<Vec<GroupRow>>;
    event_log_insert(session_id: &str, ts: i64, event_type: &str, payload_json: &str) -> rusqlite::Result<()>;
    event_log_list(session_id: &str, before_id: i64, type_filter: Option<&str>, limit: u32) -> rusqlite::Result<Vec<EventLogRow>>;
    event_log_prune(session_id: &str, keep_max: i64, age_cutoff_ms: i64) -> rusqlite::Result<usize>;
    metrics_sample_insert_batch(rows: &[(&str, i64, f64)]) -> rusqlite::Result<usize>;
    metrics_history(name: &str, since_ts: i64, limit: u32) -> rusqlite::Result<Vec<MetricPoint>>;
    metrics_names() -> rusqlite::Result<Vec<String>>;
    metrics_prune(age_cutoff: i64) -> rusqlite::Result<usize>;
    log_ring_insert_batch(rows: &[(i64, i32, &str, &str, &str)]) -> rusqlite::Result<usize>;
    log_ring_query(min_sev: i32, before_id: i64, limit: u32) -> rusqlite::Result<Vec<LogRow>>;
    log_ring_prune(keep_max: i64, age_cutoff_ms: i64) -> rusqlite::Result<usize>;
}

// Egress-target delegators. Kept out of `store_delegate!` so each can carry
// `#[allow(dead_code)]`: the store layer (item A1) lands before its callers
// (webhook/queue routes + delivery worker, items A3/A4), same forward-declared
// pattern as `SessionEvent`. Drop the allows once A3 wires them.
impl Store {
    #[allow(dead_code)]
    pub fn egress_set(&self, t: &EgressTarget) -> rusqlite::Result<()> {
        match self {
            Store::Sqlite(s) => s.egress_set(t),
            Store::Postgres(p) => pg_offload(|| p.egress_set(t)),
        }
    }
    #[allow(dead_code)]
    pub fn egress_get(&self, session_id: &str, kind: &str) -> rusqlite::Result<Option<EgressTarget>> {
        match self {
            Store::Sqlite(s) => s.egress_get(session_id, kind),
            Store::Postgres(p) => pg_offload(|| p.egress_get(session_id, kind)),
        }
    }
    #[allow(dead_code)]
    pub fn egress_list_for_session(&self, session_id: &str) -> rusqlite::Result<Vec<EgressTarget>> {
        match self {
            Store::Sqlite(s) => s.egress_list_for_session(session_id),
            Store::Postgres(p) => pg_offload(|| p.egress_list_for_session(session_id)),
        }
    }
    #[allow(dead_code)]
    pub fn egress_list_all(&self) -> rusqlite::Result<Vec<EgressTarget>> {
        match self {
            Store::Sqlite(s) => s.egress_list_all(),
            Store::Postgres(p) => pg_offload(|| p.egress_list_all()),
        }
    }
    #[allow(dead_code)]
    pub fn egress_delete(&self, session_id: &str, kind: &str) -> rusqlite::Result<()> {
        match self {
            Store::Sqlite(s) => s.egress_delete(session_id, kind),
            Store::Postgres(p) => pg_offload(|| p.egress_delete(session_id, kind)),
        }
    }
}

/// SQLite storage backend (r2d2 pool). Holds all the concrete SQL.
pub struct SqliteStore {
    pool: Pool,
}

impl SqliteStore {
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path_str = path.as_ref().to_string_lossy().into_owned();
        // A `:memory:` (or `mode=memory`) db is private to each connection, so a
        // pool of >1 would hand out empty databases. Pin it to a single reused
        // connection — equivalent to the old `Mutex<Connection>`.
        let in_memory = path_str == ":memory:" || path_str.contains("mode=memory");

        // Default synchronous=NORMAL; flip to FULL for stronger fsync guarantees
        // when RUWA_SQLITE_FULL_SYNC=1 is set. NORMAL is fine for chat data; FULL
        // eats latency under load but never loses committed txns under power loss.
        let sync_mode = match std::env::var("RUWA_SQLITE_FULL_SYNC").as_deref() {
            Ok("1") | Ok("true") | Ok("yes") => "FULL",
            _ => "NORMAL",
        }
        .to_string();

        let base = if in_memory {
            SqliteConnectionManager::memory()
        } else {
            SqliteConnectionManager::file(path.as_ref())
        };
        // Per-connection init: WAL + pragmas + a busy timeout so writers on
        // sibling pooled connections wait their turn instead of erroring SQLITE_BUSY.
        let manager = base.with_init(move |c| {
            c.busy_timeout(std::time::Duration::from_secs(5))?;
            c.pragma_update(None, "journal_mode", "WAL")?;
            c.pragma_update(None, "synchronous", sync_mode.as_str())?;
            c.pragma_update(None, "foreign_keys", "ON")?;
            Ok(())
        });

        let max_size = if in_memory {
            1
        } else {
            std::env::var("RUWA_DB_POOL_SIZE")
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok())
                .unwrap_or(8)
                .max(1)
        };
        let pool = r2d2::Pool::builder().max_size(max_size).build(manager)?;

        // Run migrations once on a checked-out connection.
        let mut conn = pool.get()?;
        migrations().to_latest(&mut conn)?;
        drop(conn);

        Ok(Self { pool })
    }

    /// Check out a pooled connection, mapping the (rare) pool-exhaustion/broken
    /// error into a `rusqlite::Error` so the `with_conn*` signature is unchanged.
    fn checkout(&self) -> rusqlite::Result<PooledConn> {
        self.pool.get().map_err(|e| {
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
                Some(format!("r2d2 pool checkout failed: {e}")),
            )
        })
    }

    pub fn with_conn<R>(
        &self,
        f: impl FnOnce(&Connection) -> rusqlite::Result<R>,
    ) -> rusqlite::Result<R> {
        let conn = self.checkout()?;
        f(&conn)
    }

    pub fn with_conn_mut<R>(
        &self,
        f: impl FnOnce(&mut Connection) -> rusqlite::Result<R>,
    ) -> rusqlite::Result<R> {
        let mut conn = self.checkout()?;
        f(&mut conn)
    }

    // ---- Domain repository methods ------------------------------------------
    //
    // Migration in progress: persistence is moving off inline SQL at call sites
    // and behind these typed methods, so a Postgres backend can slot in (and so
    // keys-at-rest sealing has a single choke point). Each group lands as its
    // own green commit. Until the trait is extracted these are inherent methods
    // on the SQLite `Store`; the signatures are already backend-neutral (raw
    // bytes + Rust-computed timestamps, no rusqlite types leak out).

    /// Load the raw Signal session record blob for `(session_id, address)`,
    /// or `None` if absent.
    pub fn signal_session_load(
        &self,
        session_id: &str,
        address: &str,
    ) -> rusqlite::Result<Option<Vec<u8>>> {
        let raw = self.with_conn(|conn| {
            conn.query_row(
                "SELECT record FROM signal_sessions WHERE session_id = ? AND address = ?",
                rusqlite::params![session_id, address],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                _ => Err(e),
            })
        })?;
        match raw {
            Some(b) => Ok(Some(unseal(b)?)),
            None => Ok(None),
        }
    }

    /// Upsert a Signal session record blob, stamping `updated_at = now` so the
    /// retention sweep sees it as freshly used. (Consolidates the two former
    /// save paths, one of which dropped `updated_at` to 0.)
    pub fn signal_session_save(
        &self,
        session_id: &str,
        address: &str,
        record: &[u8],
        now: i64,
    ) -> rusqlite::Result<()> {
        let record = vault::seal(record);
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO signal_sessions (session_id, address, record, updated_at) \
                 VALUES (?, ?, ?, ?)",
                rusqlite::params![session_id, address, record, now],
            )?;
            Ok(())
        })
    }

    /// Drop the Signal session record for one (session, address). Used to
    /// consolidate PN/LID duplicates onto a single canonical address and to
    /// reset a diverged session so the next send bootstraps a fresh, decryptable
    /// ratchet. No-op if absent.
    pub fn signal_session_delete(&self, session_id: &str, address: &str) -> rusqlite::Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "DELETE FROM signal_sessions WHERE session_id = ? AND address = ?",
                rusqlite::params![session_id, address],
            )?;
            Ok(())
        })
    }

    // ---- Group sender keys ---------------------------------------------------

    /// Load a group sender-key receiver record for (group, sender). Sealed
    /// like signal sessions (it carries chain-key material).
    pub fn sender_key_load(
        &self,
        session_id: &str,
        group_id: &str,
        sender: &str,
    ) -> rusqlite::Result<Option<Vec<u8>>> {
        let raw = self.with_conn(|conn| {
            conn.query_row(
                "SELECT record FROM sender_keys \
                 WHERE session_id = ? AND group_id = ? AND sender = ?",
                rusqlite::params![session_id, group_id, sender],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                _ => Err(e),
            })
        })?;
        match raw {
            Some(b) => Ok(Some(unseal(b)?)),
            None => Ok(None),
        }
    }

    /// Upsert a group sender-key receiver record for (group, sender).
    pub fn sender_key_save(
        &self,
        session_id: &str,
        group_id: &str,
        sender: &str,
        record: &[u8],
    ) -> rusqlite::Result<()> {
        let record = vault::seal(record);
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO sender_keys (session_id, group_id, sender, record) \
                 VALUES (?, ?, ?, ?)",
                rusqlite::params![session_id, group_id, sender, record],
            )?;
            Ok(())
        })
    }

    // ---- LID <-> PN mapping --------------------------------------------------

    /// Record a LID<->PN correspondence (user parts only). Upsert keyed by lid.
    pub fn lid_pn_put(
        &self,
        session_id: &str,
        lid_user: &str,
        pn_user: &str,
        now: i64,
    ) -> rusqlite::Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO lid_pn_map (session_id, lid_user, pn_user, updated_at) \
                 VALUES (?, ?, ?, ?)",
                rusqlite::params![session_id, lid_user, pn_user, now],
            )?;
            Ok(())
        })
    }

    /// The PN user mapped to this LID user, if known.
    pub fn lid_to_pn(&self, session_id: &str, lid_user: &str) -> rusqlite::Result<Option<String>> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT pn_user FROM lid_pn_map WHERE session_id = ? AND lid_user = ?",
                rusqlite::params![session_id, lid_user],
                |r| r.get::<_, String>(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                _ => Err(e),
            })
        })
    }

    /// The LID user mapped to this PN user, if known (most-recent wins).
    pub fn pn_to_lid(&self, session_id: &str, pn_user: &str) -> rusqlite::Result<Option<String>> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT lid_user FROM lid_pn_map WHERE session_id = ? AND pn_user = ? \
                 ORDER BY updated_at DESC LIMIT 1",
                rusqlite::params![session_id, pn_user],
                |r| r.get::<_, String>(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                _ => Err(e),
            })
        })
    }

    // ---- message secrets ----------------------------------------------------

    /// Record the original message's secret so a later `SecretEncryptedMessage`
    /// edit referencing it can be unsealed. First-writer-wins (a message id is
    /// stable); the secret is sealed at rest. `sender_jid` is stored in `ToNonAD`
    /// form because it feeds the HKDF use-case string at decrypt time.
    pub fn message_secret_put(
        &self,
        session_id: &str,
        message_id: &str,
        chat_jid: &str,
        sender_jid: &str,
        secret: &[u8],
        now: i64,
    ) -> rusqlite::Result<()> {
        let sealed = vault::seal(secret);
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR IGNORE INTO message_secrets \
                 (session_id, message_id, chat_jid, sender_jid, secret, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?)",
                rusqlite::params![session_id, message_id, chat_jid, sender_jid, sealed, now],
            )?;
            Ok(())
        })
    }

    /// The `(sender_jid, secret)` recorded for `message_id`, if any.
    pub fn message_secret_get(
        &self,
        session_id: &str,
        message_id: &str,
    ) -> rusqlite::Result<Option<(String, Vec<u8>)>> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT sender_jid, secret FROM message_secrets \
                 WHERE session_id = ? AND message_id = ?",
                rusqlite::params![session_id, message_id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                _ => Err(e),
            })
        })
        .and_then(|opt| match opt {
            Some((sender, blob)) => Ok(Some((sender, unseal(blob)?))),
            None => Ok(None),
        })
    }

    // ---- prekeys ------------------------------------------------------------

    /// Count of one-time prekeys still held by the server (`uploaded = 1`).
    pub fn prekey_count_uploaded(&self, session_id: &str) -> rusqlite::Result<i64> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM prekeys WHERE session_id = ? AND uploaded = 1",
                rusqlite::params![session_id],
                |r| r.get(0),
            )
        })
    }

    /// `(key_id, public_key)` for up to `limit` not-yet-uploaded OTKs, ascending.
    pub fn prekeys_pending_upload(
        &self,
        session_id: &str,
        limit: u32,
    ) -> rusqlite::Result<Vec<(u32, Vec<u8>)>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT key_id, public_key FROM prekeys \
                 WHERE session_id = ? AND uploaded = 0 ORDER BY key_id LIMIT ?",
            )?;
            let rows = stmt
                .query_map(rusqlite::params![session_id, limit], |r| {
                    Ok((r.get::<_, i64>(0)? as u32, r.get::<_, Vec<u8>>(1)?))
                })?
                .collect::<rusqlite::Result<_>>()?;
            Ok(rows)
        })
    }

    /// Mark every OTK with `key_id <= up_to` as uploaded.
    pub fn prekeys_mark_uploaded(&self, session_id: &str, up_to: u32) -> rusqlite::Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE prekeys SET uploaded = 1 WHERE session_id = ? AND key_id <= ?",
                rusqlite::params![session_id, up_to as i64],
            )?;
            Ok(())
        })
    }

    /// Highest existing OTK key_id for the session (0 if none) — the sequence
    /// cursor for generating the next batch.
    pub fn prekey_max_id(&self, session_id: &str) -> rusqlite::Result<u32> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT COALESCE(MAX(key_id), 0) FROM prekeys WHERE session_id = ?",
                rusqlite::params![session_id],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n as u32)
        })
    }

    /// Insert a batch of fresh (unuploaded) OTKs atomically. Each entry is
    /// `(key_id, private_key, public_key)`. Returns the count inserted.
    pub fn prekeys_insert_batch(
        &self,
        session_id: &str,
        batch: &[(u32, &[u8], &[u8])],
    ) -> rusqlite::Result<usize> {
        self.with_conn_mut(|conn| {
            let tx = conn.transaction()?;
            {
                let mut stmt = tx.prepare(
                    "INSERT INTO prekeys (session_id, key_id, private_key, public_key, uploaded) \
                     VALUES (?, ?, ?, ?, 0)",
                )?;
                for (key_id, priv_, pub_) in batch {
                    let sealed_priv = vault::seal(priv_);
                    stmt.execute(rusqlite::params![session_id, key_id, sealed_priv, pub_])?;
                }
            }
            tx.commit()?;
            Ok(batch.len())
        })
    }

    /// The private bytes of one OTK by id, or `None` if absent.
    pub fn prekey_load_private(
        &self,
        session_id: &str,
        key_id: u32,
    ) -> rusqlite::Result<Option<Vec<u8>>> {
        let raw = self.with_conn(|conn| {
            conn.query_row(
                "SELECT private_key FROM prekeys WHERE session_id = ? AND key_id = ?",
                rusqlite::params![session_id, key_id],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                _ => Err(e),
            })
        })?;
        match raw {
            Some(b) => Ok(Some(unseal(b)?)),
            None => Ok(None),
        }
    }

    /// Delete one OTK by id (single-use consumption).
    pub fn prekey_delete(&self, session_id: &str, key_id: u32) -> rusqlite::Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "DELETE FROM prekeys WHERE session_id = ? AND key_id = ?",
                rusqlite::params![session_id, key_id],
            )?;
            Ok(())
        })
    }

    // ---- messages -----------------------------------------------------------

    /// Insert a message row. `ignore_conflict` uses INSERT-OR-IGNORE for the
    /// idempotent inbound-dedup path; otherwise a plain insert. `status = None`
    /// falls back to the column default (`received`).
    pub fn message_insert(&self, m: &NewMessage, ignore_conflict: bool) -> rusqlite::Result<()> {
        let verb = if ignore_conflict {
            "INSERT OR IGNORE"
        } else {
            "INSERT"
        };
        let sql = format!(
            "{verb} INTO messages \
                (session_id, chat_jid, message_id, sender_jid, from_me, \
                 timestamp, msg_type, body_text, payload_json, status) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, 'received'))"
        );
        self.with_conn(|conn| {
            conn.execute(
                &sql,
                rusqlite::params![
                    m.session_id,
                    m.chat_jid,
                    m.message_id,
                    m.sender_jid,
                    m.from_me as i64,
                    m.timestamp,
                    m.msg_type,
                    m.body_text,
                    m.payload_json,
                    m.status,
                ],
            )?;
            Ok(())
        })
    }

    /// Insert many message rows in one transaction (history backfill). Honors
    /// `ignore_conflict` like [`Self::message_insert`].
    pub fn messages_insert_batch(
        &self,
        rows: &[NewMessage],
        ignore_conflict: bool,
    ) -> rusqlite::Result<usize> {
        let verb = if ignore_conflict {
            "INSERT OR IGNORE"
        } else {
            "INSERT"
        };
        let sql = format!(
            "{verb} INTO messages \
                (session_id, chat_jid, message_id, sender_jid, from_me, \
                 timestamp, msg_type, body_text, payload_json, status) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, 'received'))"
        );
        self.with_conn_mut(|conn| {
            let tx = conn.transaction()?;
            let mut count = 0usize;
            {
                let mut stmt = tx.prepare(&sql)?;
                for m in rows {
                    count += stmt.execute(rusqlite::params![
                        m.session_id,
                        m.chat_jid,
                        m.message_id,
                        m.sender_jid,
                        m.from_me as i64,
                        m.timestamp,
                        m.msg_type,
                        m.body_text,
                        m.payload_json,
                        m.status,
                    ])?;
                }
            }
            tx.commit()?;
            Ok(count)
        })
    }

    /// Retention prune in one transaction. Each step is skipped when its arg is
    /// `None`. Returns `(messages_aged_out, messages_over_cap, signal_pruned)`.
    /// Cutoffs are precomputed by the caller (backend-neutral time).
    pub fn prune(
        &self,
        msg_age_cutoff: Option<i64>,
        messages_per_chat: Option<u32>,
        signal_age_cutoff: Option<i64>,
    ) -> rusqlite::Result<(usize, usize, usize)> {
        self.with_conn_mut(|conn| {
            let tx = conn.transaction()?;
            let mut aged_out = 0;
            let mut over_cap = 0;
            let mut signal_pruned = 0;
            if let Some(cutoff) = msg_age_cutoff {
                aged_out = tx.execute(
                    "DELETE FROM messages WHERE timestamp < ?",
                    rusqlite::params![cutoff],
                )?;
                // Message secrets age out on the same clock as messages — a
                // secret is only useful while its original message is around to
                // be edited.
                tx.execute(
                    "DELETE FROM message_secrets WHERE created_at > 0 AND created_at < ?",
                    rusqlite::params![cutoff],
                )?;
            }
            if let Some(keep) = messages_per_chat {
                // Keep the newest N per (session, chat); trim the tail.
                over_cap = tx.execute(
                    "DELETE FROM messages WHERE rowid IN (\
                        SELECT rowid FROM (\
                            SELECT rowid, ROW_NUMBER() OVER (\
                                PARTITION BY session_id, chat_jid \
                                ORDER BY timestamp DESC, message_id DESC\
                            ) AS rn FROM messages\
                        ) WHERE rn > ?\
                    )",
                    rusqlite::params![keep],
                )?;
            }
            if let Some(cutoff) = signal_age_cutoff {
                signal_pruned = tx.execute(
                    "DELETE FROM signal_sessions WHERE updated_at > 0 AND updated_at < ?",
                    rusqlite::params![cutoff],
                )?;
            }
            tx.commit()?;
            Ok((aged_out, over_cap, signal_pruned))
        })
    }

    /// Apply an edit to the original message IN PLACE: set `edited = 1` and,
    /// when `new_body` is `Some`, replace `body_text`. Matched by id across any
    /// chat (ids are unique per session). Returns whether a row was updated —
    /// `false` means we don't have the original (predates storage / pruned), so
    /// the caller can fall back to surfacing a standalone edit marker.
    pub fn message_mark_edited(
        &self,
        session_id: &str,
        message_id: &str,
        new_body: Option<&str>,
    ) -> rusqlite::Result<bool> {
        self.with_conn(|conn| {
            let n = match new_body {
                Some(b) => conn.execute(
                    "UPDATE messages SET body_text = ?, edited = 1 \
                     WHERE session_id = ? AND message_id = ?",
                    rusqlite::params![b, session_id, message_id],
                )?,
                None => conn.execute(
                    "UPDATE messages SET edited = 1 WHERE session_id = ? AND message_id = ?",
                    rusqlite::params![session_id, message_id],
                )?,
            };
            Ok(n > 0)
        })
    }

    /// Set an outbound message row's lifecycle `status`. Idempotent.
    pub fn message_set_status(
        &self,
        session_id: &str,
        message_id: &str,
        status: &str,
    ) -> rusqlite::Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE messages SET status = ? WHERE session_id = ? AND message_id = ?",
                rusqlite::params![status, session_id, message_id],
            )?;
            Ok(())
        })
    }

    /// One-time backfill: flip `from_me` for already-stored messages whose
    /// sender is our own account. Own group fan-outs were saved `from_me=0`
    /// before the participant-based self-check landed; a message whose sender is
    /// us is from us by definition. Matches the canonical PN form and, when
    /// known, the bare own LID form. Idempotent; returns rows updated.
    pub fn messages_mark_self_from_me(
        &self,
        session_id: &str,
        own_pn_user: &str,
        own_lid_user: Option<&str>,
    ) -> rusqlite::Result<usize> {
        let pn = format!("{own_pn_user}@s.whatsapp.net");
        // Empty string can't equal any stored sender_jid, so a missing LID just
        // means "match PN only".
        let lid = own_lid_user.map(|l| format!("{l}@lid")).unwrap_or_default();
        self.with_conn(|conn| {
            let n = conn.execute(
                "UPDATE messages SET from_me = 1 \
                  WHERE session_id = ?1 AND from_me = 0 AND sender_jid IN (?2, ?3)",
                rusqlite::params![session_id, pn, lid],
            )?;
            Ok(n)
        })
    }

    /// Merge a contact's duplicate `@lid` 1:1 chat into their phone-number chat
    /// using `lid_pn_map` (a group-only contact gets a LID chat AND, once their
    /// PN is learned, a PN chat — the same person shown twice). Re-keys every
    /// `{lid}@lid` message row to `{pn}@s.whatsapp.net` where a mapping exists and
    /// no PN row with the same `message_id` already exists, then drops the
    /// leftover `@lid` duplicates. Idempotent. Groups (`@g.us`) are untouched.
    pub fn consolidate_lid_chats(&self, session_id: &str) -> rusqlite::Result<usize> {
        self.with_conn_mut(|conn| {
            let tx = conn.transaction()?;
            let n = tx.execute(
                "UPDATE messages SET chat_jid = ( \
                     SELECT m.pn_user || '@s.whatsapp.net' FROM lid_pn_map m \
                      WHERE m.session_id = ?1 AND m.lid_user = replace(messages.chat_jid, '@lid', '')) \
                  WHERE session_id = ?1 AND chat_jid LIKE '%@lid' \
                    AND EXISTS (SELECT 1 FROM lid_pn_map m WHERE m.session_id = ?1 \
                                AND m.lid_user = replace(messages.chat_jid, '@lid', '')) \
                    AND NOT EXISTS (SELECT 1 FROM messages p JOIN lid_pn_map m \
                                      ON m.session_id = ?1 AND m.lid_user = replace(messages.chat_jid, '@lid', '') \
                                    WHERE p.session_id = ?1 \
                                      AND p.chat_jid = m.pn_user || '@s.whatsapp.net' \
                                      AND p.message_id = messages.message_id)",
                rusqlite::params![session_id],
            )?;
            // Any @lid row still carrying a mapping is a true duplicate of a PN row.
            tx.execute(
                "DELETE FROM messages WHERE session_id = ?1 AND chat_jid LIKE '%@lid' \
                   AND EXISTS (SELECT 1 FROM lid_pn_map m WHERE m.session_id = ?1 \
                               AND m.lid_user = replace(messages.chat_jid, '@lid', ''))",
                rusqlite::params![session_id],
            )?;
            // Mirror the re-key onto the metadata `chats` table (pinned/archived).
            tx.execute(
                "UPDATE OR IGNORE chats SET jid = ( \
                     SELECT m.pn_user || '@s.whatsapp.net' FROM lid_pn_map m \
                      WHERE m.session_id = ?1 AND m.lid_user = replace(chats.jid, '@lid', '')) \
                  WHERE session_id = ?1 AND jid LIKE '%@lid' \
                    AND EXISTS (SELECT 1 FROM lid_pn_map m WHERE m.session_id = ?1 \
                                AND m.lid_user = replace(chats.jid, '@lid', ''))",
                rusqlite::params![session_id],
            )?;
            // Drop any leftover @lid `chats` row (re-keyed → gone; a dup of an
            // existing PN row → removed) so the merged contact shows once.
            tx.execute(
                "DELETE FROM chats WHERE session_id = ?1 AND jid LIKE '%@lid' \
                   AND EXISTS (SELECT 1 FROM lid_pn_map m WHERE m.session_id = ?1 \
                               AND m.lid_user = replace(chats.jid, '@lid', ''))",
                rusqlite::params![session_id],
            )?;
            tx.commit()?;
            Ok(n)
        })
    }

    // ---- sessions / device keys --------------------------------------------

    /// Create a session row and its initial one-time prekey batch in one
    /// transaction. The four private-key blobs (`noise_priv`, `identity_priv`,
    /// `spk_priv`, `adv_secret`) plus each prekey private are the secret
    /// material — this is their single write choke point for keys-at-rest.
    pub fn create_session(
        &self,
        s: &NewSession,
        prekeys: &[(u32, &[u8], &[u8])],
    ) -> rusqlite::Result<()> {
        // Seal the four secret columns before they touch the row.
        let noise_priv = vault::seal(s.noise_priv);
        let identity_priv = vault::seal(s.identity_priv);
        let spk_priv = vault::seal(s.spk_priv);
        let adv_secret = vault::seal(s.adv_secret);
        self.with_conn_mut(|conn| {
            let tx = conn.transaction()?;
            tx.execute(
                "INSERT INTO sessions (\
                    id, label, status, jid, registration_id, \
                    noise_key_priv, noise_key_pub, \
                    identity_key_priv, identity_key_pub, \
                    signed_prekey_id, signed_prekey_priv, signed_prekey_pub, signed_prekey_sig, \
                    adv_secret_key, api_key, \
                    created_at, updated_at\
                 ) VALUES (?,?,?,?,?, ?,?, ?,?, ?,?,?,?, ?,?, ?,?)",
                rusqlite::params![
                    s.id,
                    s.label,
                    s.status,
                    s.jid,
                    s.registration_id,
                    noise_priv,
                    s.noise_pub,
                    identity_priv,
                    s.identity_pub,
                    s.spk_id,
                    spk_priv,
                    s.spk_pub,
                    s.spk_sig,
                    adv_secret,
                    s.api_key,
                    s.created_at,
                    s.updated_at,
                ],
            )?;
            {
                let mut stmt = tx.prepare(
                    "INSERT INTO prekeys (session_id, key_id, private_key, public_key, uploaded) \
                     VALUES (?, ?, ?, ?, 0)",
                )?;
                for (key_id, priv_, pub_) in prekeys {
                    let sealed_priv = vault::seal(priv_);
                    stmt.execute(rusqlite::params![s.id, key_id, sealed_priv, pub_])?;
                }
            }
            tx.commit()?;
            Ok(())
        })
    }

    /// Replace a session's device keys with a fresh set and clear all paired +
    /// crypto state, IN PLACE (id/label/api_key/proxy/webhooks survive). Used by
    /// logout `fresh=true` so the next pairing registers a genuinely NEW device
    /// — like whatsmeow's `NewDevice` / a fresh WhatsApp-Web link — instead of
    /// re-pairing the same (possibly degraded) identity. Clears peer sessions,
    /// sender keys, one-time prekeys, app-state and the remote-identity cache;
    /// user data (messages/chats/contacts) is left untouched.
    pub fn reset_device_keys(
        &self,
        r: &DeviceKeyReset,
        prekeys: &[(u32, &[u8], &[u8])],
    ) -> rusqlite::Result<()> {
        let noise_priv = vault::seal(r.noise_priv);
        let identity_priv = vault::seal(r.identity_priv);
        let spk_priv = vault::seal(r.spk_priv);
        let adv_secret = vault::seal(r.adv_secret);
        self.with_conn_mut(|conn| {
            let tx = conn.transaction()?;
            tx.execute(
                "UPDATE sessions SET \
                    registration_id = ?, \
                    noise_key_priv = ?, noise_key_pub = ?, \
                    identity_key_priv = ?, identity_key_pub = ?, \
                    signed_prekey_id = ?, signed_prekey_priv = ?, signed_prekey_pub = ?, signed_prekey_sig = ?, \
                    adv_secret_key = ?, \
                    jid = NULL, account_pb = NULL, business_name = NULL, platform = NULL, \
                    push_name = NULL, server_token = NULL, client_token = NULL, \
                    status = 'logged_out', updated_at = ? \
                 WHERE id = ?",
                rusqlite::params![
                    r.registration_id,
                    noise_priv, r.noise_pub,
                    identity_priv, r.identity_pub,
                    r.spk_id, spk_priv, r.spk_pub, r.spk_sig,
                    adv_secret, r.updated_at, r.id,
                ],
            )?;
            for table in [
                "signal_sessions", "sender_keys", "prekeys",
                "app_state_versions", "app_state_mac_keys", "remote_identities",
            ] {
                tx.execute(
                    &format!("DELETE FROM {table} WHERE session_id = ?"),
                    rusqlite::params![r.id],
                )?;
            }
            {
                let mut stmt = tx.prepare(
                    "INSERT INTO prekeys (session_id, key_id, private_key, public_key, uploaded) \
                     VALUES (?, ?, ?, ?, 0)",
                )?;
                for (key_id, priv_, pub_) in prekeys {
                    let sealed_priv = vault::seal(priv_);
                    stmt.execute(rusqlite::params![r.id, key_id, sealed_priv, pub_])?;
                }
            }
            tx.commit()?;
            Ok(())
        })
    }

    /// Load the device-key columns for a session, or `None` if it's gone. The
    /// secret-blob read choke point (mirror of `create_session`).
    pub fn device_keys_load(&self, id: &str) -> rusqlite::Result<Option<DeviceKeyRow>> {
        let row = self.with_conn(|conn| {
            conn.query_row(
                "SELECT registration_id, \
                        noise_key_priv, noise_key_pub, \
                        identity_key_priv, identity_key_pub, \
                        signed_prekey_id, signed_prekey_priv, signed_prekey_pub, signed_prekey_sig, \
                        adv_secret_key \
                 FROM sessions WHERE id = ?",
                [id],
                |r| {
                    Ok(DeviceKeyRow {
                        registration_id: r.get::<_, i64>(0)? as u32,
                        noise_priv: r.get(1)?,
                        noise_pub: r.get(2)?,
                        identity_priv: r.get(3)?,
                        identity_pub: r.get(4)?,
                        spk_id: r.get::<_, i64>(5)? as u32,
                        spk_priv: r.get(6)?,
                        spk_pub: r.get(7)?,
                        spk_sig: r.get(8)?,
                        adv_secret: r.get(9)?,
                    })
                },
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                _ => Err(e),
            })
        })?;
        // Unseal the four secret columns; public/signature columns are stored
        // in the clear.
        match row {
            Some(mut row) => {
                row.noise_priv = unseal(row.noise_priv)?;
                row.identity_priv = unseal(row.identity_priv)?;
                row.spk_priv = unseal(row.spk_priv)?;
                row.adv_secret = unseal(row.adv_secret)?;
                Ok(Some(row))
            }
            None => Ok(None),
        }
    }

    /// Overwrite a session's `adv_secret_key` (sealed). Phone-code pairing
    /// *derives* the adv secret during the link-code handshake (rather than
    /// using the random one minted at session creation), so it must replace the
    /// stored value before `<pair-success>` HMAC-verifies against it.
    pub fn device_keys_set_adv_secret(&self, id: &str, adv_secret: &[u8]) -> rusqlite::Result<()> {
        let sealed = vault::seal(adv_secret);
        self.with_conn_mut(|conn| {
            conn.execute(
                "UPDATE sessions SET adv_secret_key = ?, updated_at = ? WHERE id = ?",
                rusqlite::params![sealed, chrono::Utc::now().timestamp(), id],
            )?;
            Ok(())
        })
    }

    /// Every session's restore-time metadata (status as the raw stored string;
    /// the caller applies its own stale-status normalization).
    pub fn sessions_all(&self) -> rusqlite::Result<Vec<SessionRow>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, label, status, jid, push_name, created_at, updated_at, proxy_url, mark_online FROM sessions",
            )?;
            let rows = stmt
                .query_map([], |r| {
                    Ok(SessionRow {
                        id: r.get(0)?,
                        label: r.get(1)?,
                        status: r.get(2)?,
                        jid: r.get(3)?,
                        push_name: r.get(4)?,
                        created_at: r.get(5)?,
                        updated_at: r.get(6)?,
                        proxy_url: r.get(7)?,
                        mark_online: r.get::<_, i64>(8)? != 0,
                    })
                })?
                .collect::<rusqlite::Result<_>>()?;
            Ok(rows)
        })
    }

    /// Read/write a session's `mark_online` presence preference (0 = announce
    /// `unavailable` so the phone keeps notifying; 1 = `available`/online).
    pub fn session_mark_online(&self, id: &str) -> rusqlite::Result<bool> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT mark_online FROM sessions WHERE id = ?1",
                [id],
                |r| Ok(r.get::<_, i64>(0)? != 0),
            )
            .or(Ok(false))
        })
    }

    pub fn session_set_mark_online(&self, id: &str, on: bool) -> rusqlite::Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE sessions SET mark_online = ?1 WHERE id = ?2",
                rusqlite::params![on as i64, id],
            )?;
            Ok(())
        })
    }

    pub fn session_delete(&self, id: &str) -> rusqlite::Result<()> {
        self.with_conn(|conn| {
            conn.execute("DELETE FROM sessions WHERE id = ?", [id])?;
            Ok(())
        })
    }

    /// The per-tenant API key, or `None` for an unknown/legacy session.
    pub fn session_api_key(&self, id: &str) -> rusqlite::Result<Option<String>> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT api_key FROM sessions WHERE id = ?",
                rusqlite::params![id],
                |r| r.get::<_, Option<String>>(0),
            )
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                _ => Err(e),
            })
        })
    }

    /// Set or clear the egress proxy URL.
    pub fn session_set_proxy(
        &self,
        id: &str,
        proxy_url: Option<&str>,
        updated_at: i64,
    ) -> rusqlite::Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE sessions SET proxy_url = ?, updated_at = ? WHERE id = ?",
                rusqlite::params![proxy_url, updated_at, id],
            )?;
            Ok(())
        })
    }

    /// Rename a session: set (or clear, with `None`) its display label.
    pub fn session_set_label(
        &self,
        id: &str,
        label: Option<&str>,
        updated_at: i64,
    ) -> rusqlite::Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE sessions SET label = ?, updated_at = ? WHERE id = ?",
                rusqlite::params![label, updated_at, id],
            )?;
            Ok(())
        })
    }

    /// The configured proxy URL, or `None`.
    pub fn session_proxy(&self, id: &str) -> rusqlite::Result<Option<String>> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT proxy_url FROM sessions WHERE id = ?",
                rusqlite::params![id],
                |r| r.get::<_, Option<String>>(0),
            )
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                _ => Err(e),
            })
        })
    }

    /// The persisted account protobuf (signed device identity), or `None`.
    pub fn session_account_pb(&self, id: &str) -> rusqlite::Result<Option<Vec<u8>>> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT account_pb FROM sessions WHERE id = ?",
                rusqlite::params![id],
                |r| r.get::<_, Option<Vec<u8>>>(0),
            )
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                _ => Err(e),
            })
        })
    }

    /// Our own push (profile) name, or `None`.
    pub fn session_push_name(&self, id: &str) -> rusqlite::Result<Option<String>> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT push_name FROM sessions WHERE id = ?",
                rusqlite::params![id],
                |r| r.get::<_, Option<String>>(0),
            )
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                _ => Err(e),
            })
        })
    }

    /// Persist our own push (profile) name (learned from our own-device message
    /// `notify`). Needed so `<presence>` carries a name — Baileys refuses to
    /// send presence without one, and a named presence is a candidate signal
    /// for the device being "open".
    pub fn session_set_push_name(&self, id: &str, name: &str) -> rusqlite::Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE sessions SET push_name = ? WHERE id = ?",
                rusqlite::params![name, id],
            )?;
            Ok(())
        })
    }

    /// Clear server-issued credentials and flip status to `logged_out`.
    pub fn session_mark_logged_out(&self, id: &str, updated_at: i64) -> rusqlite::Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE sessions SET \
                    jid = NULL, account_pb = NULL, business_name = NULL, platform = NULL, \
                    push_name = NULL, server_token = NULL, client_token = NULL, \
                    status = 'logged_out', updated_at = ? \
                 WHERE id = ?",
                rusqlite::params![updated_at, id],
            )?;
            Ok(())
        })
    }

    /// Persist pair-success: account protobuf, biz/platform/jid, status=connected.
    pub fn session_apply_pair_success(
        &self,
        id: &str,
        account_pb: &[u8],
        biz_name: Option<&str>,
        platform: Option<&str>,
        jid: Option<&str>,
        updated_at: i64,
    ) -> rusqlite::Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE sessions SET \
                    account_pb = ?, business_name = ?, platform = ?, jid = ?, \
                    status = 'connected', updated_at = ? \
                 WHERE id = ?",
                rusqlite::params![account_pb, biz_name, platform, jid, updated_at, id],
            )?;
            Ok(())
        })
    }

    // ---- session leases -----------------------------------------------------

    /// Acquire/affirm the lease via one conditional UPSERT (the conflict update
    /// fires only when we already own it or the existing lease is stale). Returns
    /// whether `owner` now holds it.
    pub fn lease_acquire(
        &self,
        session_id: &str,
        owner: &str,
        ttl: i64,
        now: i64,
    ) -> rusqlite::Result<bool> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO session_leases (session_id, owner_id, heartbeat_ts, ttl) \
                 VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(session_id) DO UPDATE SET \
                     owner_id = excluded.owner_id, \
                     heartbeat_ts = excluded.heartbeat_ts, \
                     ttl = excluded.ttl \
                 WHERE session_leases.owner_id = excluded.owner_id \
                    OR session_leases.heartbeat_ts + session_leases.ttl < excluded.heartbeat_ts",
                rusqlite::params![session_id, owner, now, ttl],
            )?;
            let held: Option<String> = conn
                .query_row(
                    "SELECT owner_id FROM session_leases WHERE session_id = ?",
                    rusqlite::params![session_id],
                    |r| r.get(0),
                )
                .ok();
            Ok(held.as_deref() == Some(owner))
        })
    }

    /// Renew our heartbeat; false ⇒ we no longer own it (stolen after staleness).
    pub fn lease_renew(&self, session_id: &str, owner: &str, now: i64) -> rusqlite::Result<bool> {
        self.with_conn(|conn| {
            let changed = conn.execute(
                "UPDATE session_leases SET heartbeat_ts = ? WHERE session_id = ? AND owner_id = ?",
                rusqlite::params![now, session_id, owner],
            )?;
            Ok(changed > 0)
        })
    }

    /// Release our lease (owner-scoped DELETE; no-op if not held).
    pub fn lease_release(&self, session_id: &str, owner: &str) -> rusqlite::Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "DELETE FROM session_leases WHERE session_id = ? AND owner_id = ?",
                rusqlite::params![session_id, owner],
            )?;
            Ok(())
        })
    }

    /// Current `(owner_id, is_stale)` for a session, or `None` if unleased.
    pub fn lease_holder(
        &self,
        session_id: &str,
        now: i64,
    ) -> rusqlite::Result<Option<(String, bool)>> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT owner_id, heartbeat_ts + ttl < ? FROM session_leases WHERE session_id = ?",
                rusqlite::params![now, session_id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                _ => Err(e),
            })
        })
    }

    // ---- outbound queue -----------------------------------------------------

    /// The persisted outbound op_json rows for a session, oldest first.
    pub fn outbound_queue_drain(&self, session_id: &str) -> rusqlite::Result<Vec<String>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT op_json FROM outbound_queue \
                 WHERE session_id = ? ORDER BY created_at ASC, msg_id ASC",
            )?;
            let out = stmt
                .query_map([session_id], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<_>>()?;
            Ok(out)
        })
    }

    /// Upsert a queued outbound op (so a reconnect can redrive it).
    pub fn outbound_queue_upsert(
        &self,
        session_id: &str,
        msg_id: &str,
        op_json: &str,
        created_at: i64,
    ) -> rusqlite::Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO outbound_queue (session_id, msg_id, op_json, created_at) \
                 VALUES (?, ?, ?, ?)",
                rusqlite::params![session_id, msg_id, op_json, created_at],
            )?;
            Ok(())
        })
    }

    /// Drop a queued op once the server has acked it.
    pub fn outbound_queue_delete(&self, session_id: &str, msg_id: &str) -> rusqlite::Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "DELETE FROM outbound_queue WHERE session_id = ? AND msg_id = ?",
                rusqlite::params![session_id, msg_id],
            )?;
            Ok(())
        })
    }

    // ---- app state ----------------------------------------------------------

    /// Current synced version for an app-state collection (0 if none yet).
    pub fn app_state_version_get(&self, session_id: &str, name: &str) -> rusqlite::Result<u64> {
        self.with_conn(|conn| {
            match conn.query_row(
                "SELECT version FROM app_state_versions WHERE session_id = ? AND name = ?",
                rusqlite::params![session_id, name],
                |r| r.get::<_, i64>(0),
            ) {
                Ok(v) => Ok(v as u64),
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
                Err(e) => Err(e),
            }
        })
    }

    /// The persisted LTHash for a collection, or `None` on first sync.
    pub fn app_state_hash_get(
        &self,
        session_id: &str,
        name: &str,
    ) -> rusqlite::Result<Option<Vec<u8>>> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT hash FROM app_state_versions WHERE session_id = ? AND name = ?",
                rusqlite::params![session_id, name],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                _ => Err(e),
            })
        })
    }

    /// Bump a collection's version (+1) and store the new LTHash.
    pub fn app_state_version_bump(
        &self,
        session_id: &str,
        name: &str,
        hash: &[u8],
    ) -> rusqlite::Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO app_state_versions (session_id, name, version, hash) \
                 VALUES (?, ?, COALESCE((SELECT version FROM app_state_versions \
                                           WHERE session_id = ? AND name = ?), 0) + 1, ?) \
                 ON CONFLICT(session_id, name) DO UPDATE SET \
                    version = app_state_versions.version + 1, \
                    hash = excluded.hash",
                rusqlite::params![session_id, name, session_id, name, hash],
            )?;
            Ok(())
        })
    }

    /// Set a collection's app-state version to an absolute value + hash. Used
    /// when applying a snapshot (which carries its own version number), vs the
    /// per-patch `_bump` which increments by one.
    pub fn app_state_version_set(
        &self,
        session_id: &str,
        name: &str,
        version: u64,
        hash: &[u8],
    ) -> rusqlite::Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO app_state_versions (session_id, name, version, hash) \
                 VALUES (?, ?, ?, ?) \
                 ON CONFLICT(session_id, name) DO UPDATE SET \
                    version = excluded.version, hash = excluded.hash",
                rusqlite::params![session_id, name, version as i64, hash],
            )?;
            Ok(())
        })
    }

    /// Save an app-state main (HMAC/LTHash) key — secret material, sealed at rest.
    pub fn app_state_main_key_save(
        &self,
        session_id: &str,
        key_id: &[u8],
        key_data: &[u8],
    ) -> rusqlite::Result<()> {
        let key_data = vault::seal(key_data);
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO app_state_mac_keys (session_id, key_id, key_data) \
                 VALUES (?, ?, ?)",
                rusqlite::params![session_id, key_id, key_data],
            )?;
            Ok(())
        })
    }

    /// Load an app-state main key (unsealed), or `None`.
    pub fn app_state_main_key_load(
        &self,
        session_id: &str,
        key_id: &[u8],
    ) -> rusqlite::Result<Option<Vec<u8>>> {
        let raw = self.with_conn(|conn| {
            conn.query_row(
                "SELECT key_data FROM app_state_mac_keys WHERE session_id = ? AND key_id = ?",
                rusqlite::params![session_id, key_id],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                _ => Err(e),
            })
        })?;
        match raw {
            Some(b) => Ok(Some(unseal(b)?)),
            None => Ok(None),
        }
    }

    // ---- contacts / chats (app-state mirror tables) -------------------------

    pub fn contact_upsert(
        &self,
        session_id: &str,
        jid: &str,
        full_name: Option<&str>,
        push_name: Option<&str>,
    ) -> rusqlite::Result<()> {
        self.with_conn(|conn| {
            // Non-destructive upsert: a push_name update must NOT wipe an
            // address-book full_name (and vice-versa). `INSERT OR REPLACE`
            // rewrote the whole row, so whichever source fired last clobbered
            // the other's column with NULL — leaving every contact name-starved.
            // COALESCE keeps the existing value when the incoming one is NULL.
            conn.execute(
                "INSERT INTO contacts (session_id, jid, full_name, push_name) \
                 VALUES (?, ?, ?, ?) \
                 ON CONFLICT(session_id, jid) DO UPDATE SET \
                   full_name = COALESCE(excluded.full_name, contacts.full_name), \
                   push_name = COALESCE(excluded.push_name, contacts.push_name)",
                rusqlite::params![session_id, jid, full_name, push_name],
            )?;
            Ok(())
        })
    }

    pub fn chat_set_pinned(&self, session_id: &str, jid: &str, pinned: bool) -> rusqlite::Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO chats (session_id, jid, pinned) VALUES (?, ?, ?) \
                 ON CONFLICT(session_id, jid) DO UPDATE SET pinned = excluded.pinned",
                rusqlite::params![session_id, jid, pinned as i32],
            )?;
            Ok(())
        })
    }

    /// Upsert a chat's display name + group flag, advancing `last_msg_ts` only
    /// forward. Used by history sync (conversation name) and group metadata so
    /// `chats_list` can surface a real name instead of a bare JID. A NULL `name`
    /// leaves any existing name untouched (COALESCE keeps the better value).
    pub fn chat_set_name(
        &self,
        session_id: &str,
        jid: &str,
        name: Option<&str>,
        is_group: bool,
        last_msg_ts: Option<i64>,
    ) -> rusqlite::Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO chats (session_id, jid, name, is_group, last_msg_ts) \
                 VALUES (?, ?, ?, ?, ?) \
                 ON CONFLICT(session_id, jid) DO UPDATE SET \
                   name = COALESCE(excluded.name, chats.name), \
                   is_group = excluded.is_group, \
                   last_msg_ts = MAX(COALESCE(excluded.last_msg_ts, 0), COALESCE(chats.last_msg_ts, 0))",
                rusqlite::params![session_id, jid, name, is_group as i32, last_msg_ts],
            )?;
            Ok(())
        })
    }

    pub fn chat_set_archived(
        &self,
        session_id: &str,
        jid: &str,
        archived: bool,
    ) -> rusqlite::Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO chats (session_id, jid, archived) VALUES (?, ?, ?) \
                 ON CONFLICT(session_id, jid) DO UPDATE SET archived = excluded.archived",
                rusqlite::params![session_id, jid, archived as i32],
            )?;
            Ok(())
        })
    }

    pub fn chat_set_muted(
        &self,
        session_id: &str,
        jid: &str,
        until: Option<i64>,
    ) -> rusqlite::Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO chats (session_id, jid, muted_until) VALUES (?, ?, ?) \
                 ON CONFLICT(session_id, jid) DO UPDATE SET muted_until = excluded.muted_until",
                rusqlite::params![session_id, jid, until],
            )?;
            Ok(())
        })
    }

    // ---- groups -------------------------------------------------------------

    /// Replace a group's metadata + full participant set in one transaction.
    /// Each participant is `(user_jid, is_admin, is_super)`.
    pub fn group_persist(
        &self,
        session_id: &str,
        jid: &str,
        subject: Option<&str>,
        creator: Option<&str>,
        creation_ts: Option<i64>,
        participants: &[(&str, bool, bool)],
    ) -> rusqlite::Result<()> {
        self.with_conn_mut(|conn| {
            let tx = conn.transaction()?;
            tx.execute(
                "INSERT OR REPLACE INTO groups (session_id, jid, subject, creator, creation_ts) \
                 VALUES (?, ?, ?, ?, ?)",
                rusqlite::params![session_id, jid, subject, creator, creation_ts],
            )?;
            tx.execute(
                "DELETE FROM group_participants WHERE session_id = ? AND group_jid = ?",
                rusqlite::params![session_id, jid],
            )?;
            {
                let mut stmt = tx.prepare(
                    "INSERT INTO group_participants \
                        (session_id, group_jid, user_jid, is_admin, is_super) \
                     VALUES (?, ?, ?, ?, ?)",
                )?;
                for (user_jid, is_admin, is_super) in participants {
                    stmt.execute(rusqlite::params![
                        session_id,
                        jid,
                        user_jid,
                        *is_admin as i32,
                        *is_super as i32,
                    ])?;
                }
            }
            tx.commit()?;
            Ok(())
        })
    }

    // ---- read/list queries (API surface) ------------------------------------

    /// Insert an outbound media message row (from_me, queued, with media_path).
    #[allow(clippy::too_many_arguments)]
    pub fn message_insert_media(
        &self,
        session_id: &str,
        chat_jid: &str,
        message_id: &str,
        sender_jid: &str,
        timestamp: i64,
        msg_type: &str,
        body_text: Option<&str>,
        payload_json: &str,
        media_path: Option<&str>,
    ) -> rusqlite::Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO messages \
                    (session_id, chat_jid, message_id, sender_jid, from_me, \
                     timestamp, msg_type, body_text, payload_json, media_path, status) \
                 VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, 'queued')",
                rusqlite::params![
                    session_id, chat_jid, message_id, sender_jid, timestamp, msg_type, body_text,
                    payload_json, media_path,
                ],
            )?;
            Ok(())
        })
    }

    /// Cache the local path of a downloaded media payload.
    pub fn message_set_media_path(
        &self,
        session_id: &str,
        chat_jid: &str,
        message_id: &str,
        media_path: &str,
    ) -> rusqlite::Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE messages SET media_path = ? \
                  WHERE session_id = ? AND chat_jid = ? AND message_id = ?",
                rusqlite::params![media_path, session_id, chat_jid, message_id],
            )?;
            Ok(())
        })
    }

    /// `(media_path, msg_type, payload_json)` for one message, or `None`.
    pub fn message_media_lookup(
        &self,
        session_id: &str,
        chat_jid: &str,
        message_id: &str,
    ) -> rusqlite::Result<Option<(Option<String>, String, String)>> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT media_path, msg_type, payload_json FROM messages \
                  WHERE session_id = ? AND chat_jid = ? AND message_id = ?",
                rusqlite::params![session_id, chat_jid, message_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                _ => Err(e),
            })
        })
    }

    /// List stored messages, newest first, with optional chat + body filter.
    pub fn messages_list(
        &self,
        session_id: &str,
        chat: Option<&str>,
        needle: Option<&str>,
        before: i64,
        limit: u32,
    ) -> rusqlite::Result<Vec<MessageListRow>> {
        self.with_conn(|conn| {
            // Ranked full-text path: when a query is present, match against the
            // FTS5 index and order by BM25 relevance (best first), not recency.
            if let Some(n) = needle {
                let Some(match_q) = fts_match_query(n) else {
                    return Ok(vec![]);
                };
                let mut sql = String::from(
                    "SELECT m.chat_jid, m.message_id, m.sender_jid, m.from_me, m.timestamp, \
                            m.msg_type, m.body_text, m.payload_json, m.edited \
                       FROM messages_fts \
                       JOIN messages m ON m.rowid = messages_fts.rowid \
                      WHERE messages_fts MATCH ?1 AND m.session_id = ?2 AND m.timestamp < ?3",
                );
                let mut params: Vec<&dyn rusqlite::ToSql> =
                    vec![&match_q, &session_id, &before];
                if let Some(c) = &chat {
                    params.push(c);
                    sql.push_str(" AND m.chat_jid = ?4");
                }
                sql.push_str(" ORDER BY bm25(messages_fts), m.timestamp DESC LIMIT ");
                sql.push_str(&limit.to_string());
                let mut stmt = conn.prepare(&sql)?;
                let rows = stmt
                    .query_map(rusqlite::params_from_iter(params), row_to_msg_list)?
                    .collect::<rusqlite::Result<_>>()?;
                return Ok(rows);
            }

            // Plain listing (no query): newest-first, optionally chat-scoped.
            let mut sql = String::from(
                "SELECT chat_jid, message_id, sender_jid, from_me, timestamp, msg_type, body_text, payload_json, edited \
                   FROM messages WHERE session_id = ?1 AND timestamp < ?2",
            );
            let mut params: Vec<&dyn rusqlite::ToSql> = vec![&session_id, &before];
            if let Some(c) = &chat {
                params.push(c);
                sql.push_str(" AND chat_jid = ?3");
            }
            sql.push_str(" ORDER BY timestamp DESC LIMIT ");
            sql.push_str(&limit.to_string());
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(params), row_to_msg_list)?
                .collect::<rusqlite::Result<_>>()?;
            Ok(rows)
        })
    }

    /// Messages around a target (`before` older + the target + `after` newer),
    /// returned chronologically. Empty if the target id isn't in the chat.
    pub fn message_context(
        &self,
        session_id: &str,
        chat: &str,
        msg_id: &str,
        before: u32,
        after: u32,
    ) -> rusqlite::Result<Vec<MessageListRow>> {
        self.with_conn(|conn| {
            let ts: Option<i64> = conn
                .query_row(
                    "SELECT timestamp FROM messages \
                       WHERE session_id = ?1 AND chat_jid = ?2 AND message_id = ?3",
                    rusqlite::params![session_id, chat, msg_id],
                    |r| r.get(0),
                )
                .map(Some)
                .or_else(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    _ => Err(e),
                })?;
            let Some(ts) = ts else { return Ok(vec![]) };
            const COLS: &str =
                "chat_jid, message_id, sender_jid, from_me, timestamp, msg_type, body_text, payload_json, edited";
            // target + `before` older, newest-first; then reverse to chronological.
            let older_sql = format!(
                "SELECT {COLS} FROM messages WHERE session_id = ?1 AND chat_jid = ?2 \
                   AND timestamp <= ?3 ORDER BY timestamp DESC, message_id DESC LIMIT {}",
                before as u64 + 1
            );
            let mut older: Vec<MessageListRow> = conn
                .prepare(&older_sql)?
                .query_map(rusqlite::params![session_id, chat, ts], row_to_msg_list)?
                .collect::<rusqlite::Result<_>>()?;
            older.reverse();
            let newer_sql = format!(
                "SELECT {COLS} FROM messages WHERE session_id = ?1 AND chat_jid = ?2 \
                   AND timestamp > ?3 ORDER BY timestamp ASC, message_id ASC LIMIT {after}"
            );
            let newer: Vec<MessageListRow> = conn
                .prepare(&newer_sql)?
                .query_map(rusqlite::params![session_id, chat, ts], row_to_msg_list)?
                .collect::<rusqlite::Result<_>>()?;
            older.extend(newer);
            Ok(older)
        })
    }

    /// The oldest stored message for a chat — `(message_id, from_me, timestamp)`
    /// — used as the anchor for an on-demand history pull. `None` if no rows.
    pub fn message_oldest_for_chat(
        &self,
        session_id: &str,
        chat: &str,
    ) -> rusqlite::Result<Option<(String, bool, i64)>> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT message_id, from_me, timestamp FROM messages \
                  WHERE session_id = ? AND chat_jid = ? \
                  ORDER BY timestamp ASC, message_id ASC LIMIT 1",
                rusqlite::params![session_id, chat],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? != 0, r.get::<_, i64>(2)?)),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                _ => Err(e),
            })
        })
    }

    pub fn contacts_list(&self, session_id: &str) -> rusqlite::Result<Vec<ContactRow>> {
        self.with_conn(|conn| {
            // Collapse a contact's `@lid` and PN rows into one: a contact created
            // under its LID before we learned its LID↔PN mapping would otherwise
            // show twice. Map each `@lid` jid to its PN via `lid_pn_map`, group by
            // the canonical jid, and fold names (MAX picks a present value over
            // NULL). Contacts with no known mapping pass through unchanged.
            let mut stmt = conn.prepare(
                "SELECT canon AS jid, MAX(full_name), MAX(push_name), MAX(business_name) \
                   FROM ( \
                     SELECT CASE \
                              WHEN c.jid LIKE '%@lid' AND m.pn_user IS NOT NULL \
                              THEN m.pn_user || '@s.whatsapp.net' ELSE c.jid END AS canon, \
                            c.full_name, c.push_name, c.business_name \
                       FROM contacts c \
                       LEFT JOIN lid_pn_map m \
                         ON m.session_id = ?1 AND m.lid_user = replace(c.jid, '@lid', '') \
                      WHERE c.session_id = ?1 \
                   ) GROUP BY canon ORDER BY canon",
            )?;
            let out = stmt
                .query_map([session_id], |r| {
                    Ok(ContactRow {
                        jid: r.get(0)?,
                        full_name: r.get(1)?,
                        push_name: r.get(2)?,
                        business_name: r.get(3)?,
                    })
                })?
                .collect::<rusqlite::Result<_>>()?;
            Ok(out)
        })
    }

    pub fn chats_list(&self, session_id: &str) -> rusqlite::Result<Vec<ChatRow>> {
        // The conversation list is derived from the `messages` table (every chat
        // that has a message), unioned with any metadata-only rows in `chats`
        // (pinned/archived/muted before a message arrived). The `chats` table by
        // itself is only written by app-state actions, so reading it alone would
        // miss every active conversation.
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                // Name resolution bridges LID↔PN: a 1:1 chat is keyed by phone
                // number, but the contact's name is often stored under their LID
                // (group senders are LID-addressed) — or vice-versa. So besides
                // the direct `contacts` join (ct), we also look up the contact
                // under the ALTERNATE addressing via `lid_pn_map`: ctl = the LID
                // row for a PN chat, ctp = the PN row for a LID chat. `juser` is
                // the bare user part of conv.jid (digits before the first
                // ./:/@). COALESCE falls back through all of them.
                "WITH conv AS ( \
                     SELECT chat_jid AS jid, MAX(timestamp) AS last_msg_ts \
                       FROM messages WHERE session_id = ?1 GROUP BY chat_jid \
                     UNION \
                     SELECT jid, last_msg_ts FROM chats \
                       WHERE session_id = ?1 \
                         AND jid NOT IN (SELECT DISTINCT chat_jid FROM messages WHERE session_id = ?1) \
                   ), convu AS ( \
                     SELECT jid, last_msg_ts, \
                            substr(jid, 1, (min( \
                              CASE WHEN instr(jid,'.')=0 THEN 1000000 ELSE instr(jid,'.') END, \
                              CASE WHEN instr(jid,':')=0 THEN 1000000 ELSE instr(jid,':') END, \
                              instr(jid,'@')) - 1)) AS juser \
                       FROM conv \
                   ) \
                   SELECT conv.jid, \
                        COALESCE(c.name, ct.full_name, ct.push_name, ct.first_name, \
                                 ctl.full_name, ctl.push_name, ctl.first_name, \
                                 ctp.full_name, ctp.push_name, ctp.first_name) AS name, \
                        CASE WHEN conv.jid LIKE '%@g.us' THEN 1 ELSE COALESCE(c.is_group, 0) END AS is_group, \
                        conv.last_msg_ts, \
                        COALESCE(c.archived, 0) AS archived, \
                        COALESCE(c.pinned, 0) AS pinned, \
                        c.muted_until \
                   FROM convu conv \
                   LEFT JOIN chats c     ON c.session_id = ?1  AND c.jid = conv.jid \
                   LEFT JOIN contacts ct ON ct.session_id = ?1 AND ct.jid = conv.jid \
                   LEFT JOIN lid_pn_map lmp ON lmp.session_id = ?1 AND lmp.pn_user = conv.juser \
                   LEFT JOIN contacts ctl   ON ctl.session_id = ?1 AND ctl.jid = lmp.lid_user || '@lid' \
                   LEFT JOIN lid_pn_map lml ON lml.session_id = ?1 AND lml.lid_user = conv.juser \
                   LEFT JOIN contacts ctp   ON ctp.session_id = ?1 AND ctp.jid = lml.pn_user || '@s.whatsapp.net' \
                  ORDER BY COALESCE(conv.last_msg_ts, 0) DESC",
            )?;
            let out = stmt
                .query_map([session_id], |r| {
                    Ok(ChatRow {
                        jid: r.get(0)?,
                        name: r.get(1)?,
                        is_group: r.get::<_, i64>(2)? != 0,
                        last_msg_ts: r.get(3)?,
                        archived: r.get::<_, i64>(4)? != 0,
                        pinned: r.get::<_, i64>(5)? != 0,
                        muted_until: r.get(6)?,
                    })
                })?
                .collect::<rusqlite::Result<_>>()?;
            Ok(out)
        })
    }

    /// PN jids (from chats AND contacts) that don't yet have a LID↔PN mapping.
    /// The lid-pn sweep resolves these via usync so the read-side contact/chat
    /// collapse can fold a contact's `@lid` duplicate into their PN row. Covers
    /// NAMED contacts too — a named contact still shows up twice (LID + PN) until
    /// its LID is mapped, which is the "same person appears as two contacts"
    /// symptom.
    pub fn pns_without_lid_mapping(
        &self,
        session_id: &str,
        limit: u32,
    ) -> rusqlite::Result<Vec<String>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT DISTINCT u.jid FROM ( \
                     SELECT chat_jid AS jid FROM messages \
                      WHERE session_id = ?1 AND chat_jid LIKE '%@s.whatsapp.net' \
                     UNION \
                     SELECT jid FROM contacts \
                      WHERE session_id = ?1 AND jid LIKE '%@s.whatsapp.net') u \
                  WHERE NOT EXISTS ( \
                      SELECT 1 FROM lid_pn_map lm \
                       WHERE lm.session_id = ?1 \
                         AND lm.pn_user = substr(u.jid, 1, (min( \
                              CASE WHEN instr(u.jid,'.')=0 THEN 1000000 ELSE instr(u.jid,'.') END, \
                              CASE WHEN instr(u.jid,':')=0 THEN 1000000 ELSE instr(u.jid,':') END, \
                              instr(u.jid,'@')) - 1))) \
                  LIMIT ?2",
            )?;
            let out = stmt
                .query_map(rusqlite::params![session_id, limit], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<_>>()?;
            Ok(out)
        })
    }

    pub fn groups_list(&self, session_id: &str) -> rusqlite::Result<Vec<GroupRow>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT jid, subject, creator, creation_ts FROM groups \
                  WHERE session_id = ? ORDER BY jid",
            )?;
            let out = stmt
                .query_map([session_id], |r| {
                    Ok(GroupRow {
                        jid: r.get(0)?,
                        subject: r.get(1)?,
                        creator: r.get(2)?,
                        creation_ts: r.get(3)?,
                    })
                })?
                .collect::<rusqlite::Result<_>>()?;
            Ok(out)
        })
    }

}

// Egress-target storage (SQLite). Its own `#[allow(dead_code)]` impl because the
// store layer (item A1) lands before its callers (items A3/A4), the same
// forward-declared pattern as `SessionEvent`. Drop the allow once A3 wires them.
#[allow(dead_code)]
impl SqliteStore {
    /// Upsert one target (PK = session_id + kind).
    pub fn egress_set(&self, t: &EgressTarget) -> rusqlite::Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO egress_targets \
                    (session_id, kind, enabled, events, secret, config, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
                 ON CONFLICT(session_id, kind) DO UPDATE SET \
                    enabled = excluded.enabled, events = excluded.events, \
                    secret = excluded.secret, config = excluded.config, \
                    updated_at = excluded.updated_at",
                rusqlite::params![
                    t.session_id,
                    t.kind,
                    t.enabled,
                    t.events,
                    t.secret,
                    t.config,
                    t.updated_at,
                ],
            )?;
            Ok(())
        })
    }

    pub fn egress_get(
        &self,
        session_id: &str,
        kind: &str,
    ) -> rusqlite::Result<Option<EgressTarget>> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT session_id, kind, enabled, events, secret, config, updated_at \
                   FROM egress_targets WHERE session_id = ?1 AND kind = ?2",
                rusqlite::params![session_id, kind],
                row_to_egress,
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                _ => Err(e),
            })
        })
    }

    pub fn egress_list_for_session(
        &self,
        session_id: &str,
    ) -> rusqlite::Result<Vec<EgressTarget>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT session_id, kind, enabled, events, secret, config, updated_at \
                   FROM egress_targets WHERE session_id = ? ORDER BY kind",
            )?;
            let out = stmt
                .query_map([session_id], row_to_egress)?
                .collect::<rusqlite::Result<_>>()?;
            Ok(out)
        })
    }

    pub fn egress_list_all(&self) -> rusqlite::Result<Vec<EgressTarget>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT session_id, kind, enabled, events, secret, config, updated_at \
                   FROM egress_targets ORDER BY session_id, kind",
            )?;
            let out = stmt
                .query_map([], row_to_egress)?
                .collect::<rusqlite::Result<_>>()?;
            Ok(out)
        })
    }

    pub fn egress_delete(&self, session_id: &str, kind: &str) -> rusqlite::Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "DELETE FROM egress_targets WHERE session_id = ?1 AND kind = ?2",
                rusqlite::params![session_id, kind],
            )?;
            Ok(())
        })
    }

    // ---- event log (dashboard Logs history) ----

    pub fn event_log_insert(
        &self,
        session_id: &str,
        ts: i64,
        event_type: &str,
        payload_json: &str,
    ) -> rusqlite::Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO event_log (session_id, ts, event_type, payload_json) \
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![session_id, ts, event_type, payload_json],
            )?;
            Ok(())
        })
    }

    /// Newest-first page of a session's events. `before_id` is a keyset cursor
    /// (pass `i64::MAX` for the first page); `type_filter` keeps only one event
    /// type when set.
    pub fn event_log_list(
        &self,
        session_id: &str,
        before_id: i64,
        type_filter: Option<&str>,
        limit: u32,
    ) -> rusqlite::Result<Vec<EventLogRow>> {
        self.with_conn(|conn| {
            let mut sql = String::from(
                "SELECT id, ts, event_type, payload_json FROM event_log \
                   WHERE session_id = ?1 AND id < ?2",
            );
            if type_filter.is_some() {
                sql.push_str(" AND event_type = ?3");
            }
            sql.push_str(" ORDER BY id DESC LIMIT ");
            sql.push_str(&limit.to_string());

            let mut stmt = conn.prepare(&sql)?;
            let map = |r: &rusqlite::Row<'_>| {
                Ok(EventLogRow {
                    id: r.get(0)?,
                    ts: r.get(1)?,
                    event_type: r.get(2)?,
                    payload_json: r.get(3)?,
                })
            };
            let rows = match type_filter {
                Some(t) => stmt
                    .query_map(rusqlite::params![session_id, before_id, t], map)?
                    .collect::<rusqlite::Result<_>>()?,
                None => stmt
                    .query_map(rusqlite::params![session_id, before_id], map)?
                    .collect::<rusqlite::Result<_>>()?,
            };
            Ok(rows)
        })
    }

    /// Bound the log: delete a session's events older than `age_cutoff_ms` OR
    /// beyond the newest `keep_max`. Returns the number of rows removed.
    pub fn event_log_prune(
        &self,
        session_id: &str,
        keep_max: i64,
        age_cutoff_ms: i64,
    ) -> rusqlite::Result<usize> {
        self.with_conn(|conn| {
            let n = conn.execute(
                "DELETE FROM event_log \
                  WHERE session_id = ?1 \
                    AND (ts < ?2 \
                         OR id NOT IN ( \
                             SELECT id FROM event_log WHERE session_id = ?1 \
                              ORDER BY id DESC LIMIT ?3))",
                rusqlite::params![session_id, age_cutoff_ms, keep_max],
            )?;
            Ok(n)
        })
    }

    /// Append a batch of metric samples in one transaction. `(name, ts, value)`;
    /// a duplicate (name, ts) is silently ignored so a double-sample at the same
    /// second can't error. Returns the number of rows actually inserted.
    pub fn metrics_sample_insert_batch(
        &self,
        rows: &[(&str, i64, f64)],
    ) -> rusqlite::Result<usize> {
        self.with_conn_mut(|conn| {
            let tx = conn.transaction()?;
            let mut n = 0;
            {
                let mut stmt = tx.prepare(
                    "INSERT INTO metrics_samples (name, ts, value) VALUES (?1, ?2, ?3) \
                     ON CONFLICT(name, ts) DO NOTHING",
                )?;
                for (name, ts, value) in rows {
                    n += stmt.execute(rusqlite::params![name, ts, value])?;
                }
            }
            tx.commit()?;
            Ok(n)
        })
    }

    /// A series' points at or after `since_ts`, oldest-first (ready to chart).
    /// Caps at the most recent `limit` points within the window.
    pub fn metrics_history(
        &self,
        name: &str,
        since_ts: i64,
        limit: u32,
    ) -> rusqlite::Result<Vec<MetricPoint>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT ts, value FROM metrics_samples \
                   WHERE name = ?1 AND ts >= ?2 \
                   ORDER BY ts DESC LIMIT ?3",
            )?;
            let mut rows: Vec<MetricPoint> = stmt
                .query_map(rusqlite::params![name, since_ts, limit], |r| {
                    Ok(MetricPoint {
                        ts: r.get(0)?,
                        value: r.get(1)?,
                    })
                })?
                .collect::<rusqlite::Result<_>>()?;
            rows.reverse(); // DESC fetch → ASC for charting
            Ok(rows)
        })
    }

    /// Distinct series names currently held, for the Console to enumerate.
    pub fn metrics_names(&self) -> rusqlite::Result<Vec<String>> {
        self.with_conn(|conn| {
            let mut stmt =
                conn.prepare("SELECT DISTINCT name FROM metrics_samples ORDER BY name")?;
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<_>>()?;
            Ok(rows)
        })
    }

    /// Drop samples older than `age_cutoff` (unix seconds). Returns rows removed.
    pub fn metrics_prune(&self, age_cutoff: i64) -> rusqlite::Result<usize> {
        self.with_conn(|conn| {
            let n = conn.execute(
                "DELETE FROM metrics_samples WHERE ts < ?1",
                rusqlite::params![age_cutoff],
            )?;
            Ok(n)
        })
    }

    /// Append a batch of process-log lines in one transaction.
    /// `(ts_ms, sev, level, target, message)`. Returns rows inserted.
    pub fn log_ring_insert_batch(
        &self,
        rows: &[(i64, i32, &str, &str, &str)],
    ) -> rusqlite::Result<usize> {
        self.with_conn_mut(|conn| {
            let tx = conn.transaction()?;
            let mut n = 0;
            {
                let mut stmt = tx.prepare(
                    "INSERT INTO log_ring (ts, sev, level, target, message) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                )?;
                for (ts, sev, level, target, message) in rows {
                    n += stmt.execute(rusqlite::params![ts, sev, level, target, message])?;
                }
            }
            tx.commit()?;
            Ok(n)
        })
    }

    /// Newest-first page of process logs at or above `min_sev`. `before_id` is a
    /// keyset cursor (pass `i64::MAX` for the first page).
    pub fn log_ring_query(
        &self,
        min_sev: i32,
        before_id: i64,
        limit: u32,
    ) -> rusqlite::Result<Vec<LogRow>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, ts, level, target, message FROM log_ring \
                   WHERE sev >= ?1 AND id < ?2 \
                   ORDER BY id DESC LIMIT ?3",
            )?;
            let rows = stmt
                .query_map(rusqlite::params![min_sev, before_id, limit], |r| {
                    Ok(LogRow {
                        id: r.get(0)?,
                        ts: r.get(1)?,
                        level: r.get(2)?,
                        target: r.get(3)?,
                        message: r.get(4)?,
                    })
                })?
                .collect::<rusqlite::Result<_>>()?;
            Ok(rows)
        })
    }

    /// Bound the ring: delete logs older than `age_cutoff_ms` OR beyond the
    /// newest `keep_max`. Returns rows removed.
    pub fn log_ring_prune(
        &self,
        keep_max: i64,
        age_cutoff_ms: i64,
    ) -> rusqlite::Result<usize> {
        self.with_conn(|conn| {
            let n = conn.execute(
                "DELETE FROM log_ring \
                  WHERE ts < ?1 \
                     OR id NOT IN (SELECT id FROM log_ring ORDER BY id DESC LIMIT ?2)",
                rusqlite::params![age_cutoff_ms, keep_max],
            )?;
            Ok(n)
        })
    }
}

/// Map a messages row in the canonical `messages_list` column order to a
/// `MessageListRow` (chat_jid, message_id, sender_jid, from_me, timestamp,
/// msg_type, body_text).
fn row_to_msg_list(r: &rusqlite::Row<'_>) -> rusqlite::Result<MessageListRow> {
    // Column 7 is `payload_json`; pull the reply quote out of it (if present).
    let quoted = r
        .get::<_, String>(7)
        .ok()
        .as_deref()
        .and_then(parse_quoted);
    Ok(MessageListRow {
        chat_jid: r.get(0)?,
        message_id: r.get(1)?,
        sender_jid: r.get(2)?,
        from_me: r.get::<_, i64>(3)? != 0,
        timestamp: r.get(4)?,
        msg_type: r.get(5)?,
        body_text: r.get(6)?,
        edited: r.get::<_, i64>(8)? != 0,
        quoted,
    })
}

/// Build a safe FTS5 `MATCH` expression from raw user input.
///
/// Each whitespace-separated word becomes a double-quoted term so FTS5 operator
/// characters (`-`, `*`, `:`, `"`, parentheses, `AND`/`OR`/`NOT`) are treated as
/// literal text rather than query syntax — a raw needle like `who's there?`
/// would otherwise be a syntax error. Space-separated terms are implicitly
/// ANDed, so all words must appear. Returns `None` when the input has no
/// indexable characters (e.g. all punctuation), in which case callers should
/// return no results.
fn fts_match_query(needle: &str) -> Option<String> {
    let mut out = String::new();
    for tok in needle.split_whitespace() {
        let cleaned: String = tok.chars().filter(|c| *c != '"').collect();
        if cleaned.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push('"');
        out.push_str(&cleaned);
        out.push('"');
    }
    (!out.is_empty()).then_some(out)
}

/// Map a `egress_targets` row (in the canonical column order) to `EgressTarget`.
#[allow(dead_code)]
fn row_to_egress(r: &rusqlite::Row<'_>) -> rusqlite::Result<EgressTarget> {
    Ok(EgressTarget {
        session_id: r.get(0)?,
        kind: r.get(1)?,
        enabled: r.get::<_, i64>(2)? != 0,
        events: r.get(3)?,
        secret: r.get(4)?,
        config: r.get(5)?,
        updated_at: r.get(6)?,
    })
}

/// The reply quote of an inbound message, parsed out of `payload_json`. Present
/// only when the message was a reply. `stanza_id` lets the client link/scroll to
/// the quoted message; `text` is a preview for when it isn't loaded.
#[derive(Serialize, Deserialize)]
pub struct QuotedInfo {
    pub stanza_id: Option<String>,
    pub participant: Option<String>,
    pub text: Option<String>,
}

/// Pull the `quoted` reply reference out of a message's `payload_json`, if present.
/// Shared by the SQLite + Postgres row mappers.
fn parse_quoted(payload_json: &str) -> Option<QuotedInfo> {
    serde_json::from_str::<serde_json::Value>(payload_json)
        .ok()
        .and_then(|v| v.get("quoted").cloned())
        .and_then(|q| serde_json::from_value::<QuotedInfo>(q).ok())
}

/// A stored message row for the list API (field names are the JSON shape).
#[derive(Serialize)]
pub struct MessageListRow {
    pub chat_jid: String,
    pub message_id: String,
    pub sender_jid: String,
    pub from_me: bool,
    pub timestamp: i64,
    pub msg_type: String,
    pub body_text: Option<String>,
    /// True when this message was edited and the new text applied in place.
    /// Omitted from JSON when false to keep payloads lean.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub edited: bool,
    /// The quoted message this is a reply to, if any (`null` for non-replies).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quoted: Option<QuotedInfo>,
}

#[derive(Serialize)]
pub struct ContactRow {
    pub jid: String,
    pub full_name: Option<String>,
    pub push_name: Option<String>,
    pub business_name: Option<String>,
}

#[derive(Serialize)]
pub struct ChatRow {
    pub jid: String,
    pub name: Option<String>,
    pub is_group: bool,
    pub last_msg_ts: Option<i64>,
    pub archived: bool,
    pub pinned: bool,
    pub muted_until: Option<i64>,
}

#[derive(Serialize)]
pub struct GroupRow {
    pub jid: String,
    pub subject: Option<String>,
    pub creator: Option<String>,
    pub creation_ts: Option<i64>,
}

/// One persisted session event (a row of `event_log`). `payload_json` is the
/// full type-tagged `SessionEvent` JSON; the API merges `id`/`ts` into it.
/// `ts` is unix milliseconds.
#[derive(Debug, Clone)]
pub struct EventLogRow {
    pub id: i64,
    pub ts: i64,
    pub event_type: String,
    pub payload_json: String,
}

/// One persisted metric sample (a row of `metrics_samples`). `ts` is unix
/// seconds; `value` is the series' reading at that second.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MetricPoint {
    pub ts: i64,
    pub value: f64,
}

/// One persisted process-log line (a row of `log_ring`). `ts` is unix ms.
#[derive(Debug, Clone)]
pub struct LogRow {
    pub id: i64,
    pub ts: i64,
    pub level: String,
    pub target: String,
    pub message: String,
}

/// Map a textual log level to its numeric severity (0 trace .. 4 error).
/// Case-insensitive; an unknown value → 0 (capture everything). Shared by the
/// capture layer's env config and the logs API's min-level filter.
pub fn log_level_sev(level: &str) -> i32 {
    match level.trim().to_ascii_lowercase().as_str() {
        "error" => 4,
        "warn" | "warning" => 3,
        "info" => 2,
        "debug" => 1,
        _ => 0,
    }
}

/// One per-session event-fan-out destination (a row of `egress_targets`).
/// `kind` is `"webhook" | "rabbitmq" | "sqs"`. `events` is a CSV allowlist of
/// `SessionEvent` type tags (`None`/empty = deliver all). `config` is a
/// transport-specific JSON blob. `secret` is the webhook HMAC key (else `None`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressTarget {
    pub session_id: String,
    pub kind: String,
    pub enabled: bool,
    pub events: Option<String>,
    pub secret: Option<String>,
    pub config: String,
    pub updated_at: i64,
}

// ===== Postgres backend ======================================================

type PgManager = r2d2_postgres::PostgresConnectionManager<postgres::NoTls>;
type PgPool = r2d2::Pool<PgManager>;
type PgConn = r2d2::PooledConnection<PgManager>;

/// Map any Postgres/pool error into a `rusqlite::Error` so PgStore methods share
/// the `rusqlite::Result` signature with SqliteStore (the enum dispatch needs
/// identical signatures). The "rusqlite" wrapper here is purely the shared error
/// channel — no SQLite is involved.
fn pg_err(e: impl std::fmt::Display) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
        Some(format!("postgres: {e}")),
    )
}

/// Postgres storage backend (sync `postgres` client via an r2d2 pool). Mirrors
/// every `SqliteStore` method in Postgres dialect (`$N` params, `ON CONFLICT`,
/// `BYTEA`/`BIGINT`, `ctid` for the per-chat cap). Keys-at-rest sealing reuses
/// the same `vault` choke points.
pub struct PgStore {
    // `Option` so `Drop` can move the pool out and tear it down on a clean OS
    // thread: idle `postgres::Client`s call `block_on` in their own `Drop`, which
    // panics if the pool is dropped on a tokio worker thread (process exit).
    pool: Option<PgPool>,
}

impl Drop for PgStore {
    fn drop(&mut self) {
        // Tear the pool down on a fresh OS thread (no ambient tokio runtime), so
        // the `postgres::Client` destructors' `block_on` doesn't panic. See
        // `pg_offload`.
        if let Some(pool) = self.pool.take() {
            let _ = std::thread::spawn(move || drop(pool)).join();
        }
    }
}

impl PgStore {
    pub fn open(url: &str) -> anyhow::Result<Self> {
        let config: postgres::Config = url.parse()?;
        let manager = PgManager::new(config, postgres::NoTls);
        let max = std::env::var("RUWA_DB_POOL_SIZE")
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(8)
            .max(1);
        let pool = r2d2::Pool::builder().max_size(max).build(manager)?;
        pool.get()?
            .batch_execute(include_str!("../migrations/postgres_schema.sql"))?;
        Ok(Self { pool: Some(pool) })
    }

    fn conn(&self) -> rusqlite::Result<PgConn> {
        self.pool.as_ref().expect("PgStore pool present").get().map_err(pg_err)
    }

    // ---- signal sessions ----
    pub fn signal_session_load(
        &self,
        session_id: &str,
        address: &str,
    ) -> rusqlite::Result<Option<Vec<u8>>> {
        let row = self
            .conn()?
            .query_opt(
                "SELECT record FROM signal_sessions WHERE session_id=$1 AND address=$2",
                &[&session_id, &address],
            )
            .map_err(pg_err)?;
        match row {
            Some(r) => Ok(Some(unseal(r.get::<_, Vec<u8>>(0))?)),
            None => Ok(None),
        }
    }

    pub fn signal_session_save(
        &self,
        session_id: &str,
        address: &str,
        record: &[u8],
        now: i64,
    ) -> rusqlite::Result<()> {
        let sealed = vault::seal(record);
        self.conn()?
            .execute(
                "INSERT INTO signal_sessions (session_id,address,record,updated_at) \
                 VALUES ($1,$2,$3,$4) \
                 ON CONFLICT (session_id,address) DO UPDATE SET \
                    record=excluded.record, updated_at=excluded.updated_at",
                &[&session_id, &address, &sealed, &now],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    pub fn signal_session_delete(&self, session_id: &str, address: &str) -> rusqlite::Result<()> {
        self.conn()?
            .execute(
                "DELETE FROM signal_sessions WHERE session_id=$1 AND address=$2",
                &[&session_id, &address],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    // ---- Group sender keys ----
    pub fn sender_key_load(
        &self,
        session_id: &str,
        group_id: &str,
        sender: &str,
    ) -> rusqlite::Result<Option<Vec<u8>>> {
        let row = self
            .conn()?
            .query_opt(
                "SELECT record FROM sender_keys \
                 WHERE session_id=$1 AND group_id=$2 AND sender=$3",
                &[&session_id, &group_id, &sender],
            )
            .map_err(pg_err)?;
        match row {
            Some(r) => Ok(Some(unseal(r.get::<_, Vec<u8>>(0))?)),
            None => Ok(None),
        }
    }

    pub fn sender_key_save(
        &self,
        session_id: &str,
        group_id: &str,
        sender: &str,
        record: &[u8],
    ) -> rusqlite::Result<()> {
        let sealed = vault::seal(record);
        self.conn()?
            .execute(
                "INSERT INTO sender_keys (session_id,group_id,sender,record) \
                 VALUES ($1,$2,$3,$4) \
                 ON CONFLICT (session_id,group_id,sender) DO UPDATE SET \
                    record=excluded.record",
                &[&session_id, &group_id, &sender, &sealed],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    // ---- LID <-> PN mapping ----
    pub fn lid_pn_put(
        &self,
        session_id: &str,
        lid_user: &str,
        pn_user: &str,
        now: i64,
    ) -> rusqlite::Result<()> {
        self.conn()?
            .execute(
                "INSERT INTO lid_pn_map (session_id,lid_user,pn_user,updated_at) \
                 VALUES ($1,$2,$3,$4) \
                 ON CONFLICT (session_id,lid_user) DO UPDATE SET \
                    pn_user=excluded.pn_user, updated_at=excluded.updated_at",
                &[&session_id, &lid_user, &pn_user, &now],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    pub fn lid_to_pn(&self, session_id: &str, lid_user: &str) -> rusqlite::Result<Option<String>> {
        let row = self
            .conn()?
            .query_opt(
                "SELECT pn_user FROM lid_pn_map WHERE session_id=$1 AND lid_user=$2",
                &[&session_id, &lid_user],
            )
            .map_err(pg_err)?;
        Ok(row.map(|r| r.get::<_, String>(0)))
    }

    pub fn pn_to_lid(&self, session_id: &str, pn_user: &str) -> rusqlite::Result<Option<String>> {
        let row = self
            .conn()?
            .query_opt(
                "SELECT lid_user FROM lid_pn_map WHERE session_id=$1 AND pn_user=$2 \
                 ORDER BY updated_at DESC LIMIT 1",
                &[&session_id, &pn_user],
            )
            .map_err(pg_err)?;
        Ok(row.map(|r| r.get::<_, String>(0)))
    }

    // ---- message secrets ----
    pub fn message_secret_put(
        &self,
        session_id: &str,
        message_id: &str,
        chat_jid: &str,
        sender_jid: &str,
        secret: &[u8],
        now: i64,
    ) -> rusqlite::Result<()> {
        let sealed = vault::seal(secret);
        self.conn()?
            .execute(
                "INSERT INTO message_secrets \
                 (session_id, message_id, chat_jid, sender_jid, secret, created_at) \
                 VALUES ($1,$2,$3,$4,$5,$6) \
                 ON CONFLICT (session_id, message_id) DO NOTHING",
                &[&session_id, &message_id, &chat_jid, &sender_jid, &sealed, &now],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    pub fn message_secret_get(
        &self,
        session_id: &str,
        message_id: &str,
    ) -> rusqlite::Result<Option<(String, Vec<u8>)>> {
        let row = self
            .conn()?
            .query_opt(
                "SELECT sender_jid, secret FROM message_secrets \
                 WHERE session_id=$1 AND message_id=$2",
                &[&session_id, &message_id],
            )
            .map_err(pg_err)?;
        match row {
            Some(r) => {
                let sender = r.get::<_, String>(0);
                let blob = r.get::<_, Vec<u8>>(1);
                Ok(Some((sender, unseal(blob)?)))
            }
            None => Ok(None),
        }
    }

    // ---- prekeys ----
    pub fn prekey_count_uploaded(&self, session_id: &str) -> rusqlite::Result<i64> {
        let row = self
            .conn()?
            .query_one(
                "SELECT COUNT(*) FROM prekeys WHERE session_id=$1 AND uploaded=1",
                &[&session_id],
            )
            .map_err(pg_err)?;
        Ok(row.get::<_, i64>(0))
    }

    pub fn prekeys_pending_upload(
        &self,
        session_id: &str,
        limit: u32,
    ) -> rusqlite::Result<Vec<(u32, Vec<u8>)>> {
        let rows = self
            .conn()?
            .query(
                "SELECT key_id, public_key FROM prekeys \
                 WHERE session_id=$1 AND uploaded=0 ORDER BY key_id LIMIT $2",
                &[&session_id, &(i64::from(limit))],
            )
            .map_err(pg_err)?;
        Ok(rows
            .iter()
            .map(|r| (r.get::<_, i64>(0) as u32, r.get::<_, Vec<u8>>(1)))
            .collect())
    }

    pub fn prekeys_mark_uploaded(&self, session_id: &str, up_to: u32) -> rusqlite::Result<()> {
        self.conn()?
            .execute(
                "UPDATE prekeys SET uploaded=1 WHERE session_id=$1 AND key_id<=$2",
                &[&session_id, &(i64::from(up_to))],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    pub fn prekey_max_id(&self, session_id: &str) -> rusqlite::Result<u32> {
        let row = self
            .conn()?
            .query_one(
                "SELECT COALESCE(MAX(key_id),0) FROM prekeys WHERE session_id=$1",
                &[&session_id],
            )
            .map_err(pg_err)?;
        Ok(row.get::<_, i64>(0) as u32)
    }

    pub fn prekeys_insert_batch(
        &self,
        session_id: &str,
        batch: &[(u32, &[u8], &[u8])],
    ) -> rusqlite::Result<usize> {
        let mut c = self.conn()?;
        let mut tx = c.transaction().map_err(pg_err)?;
        for (key_id, priv_, pub_) in batch {
            let sealed = vault::seal(priv_);
            tx.execute(
                "INSERT INTO prekeys (session_id,key_id,private_key,public_key,uploaded) \
                 VALUES ($1,$2,$3,$4,0)",
                &[&session_id, &(i64::from(*key_id)), &sealed, pub_],
            )
            .map_err(pg_err)?;
        }
        tx.commit().map_err(pg_err)?;
        Ok(batch.len())
    }

    pub fn prekey_load_private(
        &self,
        session_id: &str,
        key_id: u32,
    ) -> rusqlite::Result<Option<Vec<u8>>> {
        let row = self
            .conn()?
            .query_opt(
                "SELECT private_key FROM prekeys WHERE session_id=$1 AND key_id=$2",
                &[&session_id, &(i64::from(key_id))],
            )
            .map_err(pg_err)?;
        match row {
            Some(r) => Ok(Some(unseal(r.get::<_, Vec<u8>>(0))?)),
            None => Ok(None),
        }
    }

    pub fn prekey_delete(&self, session_id: &str, key_id: u32) -> rusqlite::Result<()> {
        self.conn()?
            .execute(
                "DELETE FROM prekeys WHERE session_id=$1 AND key_id=$2",
                &[&session_id, &(i64::from(key_id))],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    // ---- messages ----
    pub fn message_insert(&self, m: &NewMessage, ignore_conflict: bool) -> rusqlite::Result<()> {
        let tail = if ignore_conflict {
            " ON CONFLICT (session_id,chat_jid,message_id) DO NOTHING"
        } else {
            ""
        };
        let sql = format!(
            "INSERT INTO messages \
                (session_id,chat_jid,message_id,sender_jid,from_me,timestamp,msg_type,body_text,payload_json,status) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,COALESCE($10,'received')){tail}"
        );
        self.conn()?
            .execute(
                sql.as_str(),
                &[
                    &m.session_id,
                    &m.chat_jid,
                    &m.message_id,
                    &m.sender_jid,
                    &(m.from_me as i64),
                    &m.timestamp,
                    &m.msg_type,
                    &m.body_text,
                    &m.payload_json,
                    &m.status,
                ],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    pub fn messages_insert_batch(
        &self,
        rows: &[NewMessage],
        ignore_conflict: bool,
    ) -> rusqlite::Result<usize> {
        let tail = if ignore_conflict {
            " ON CONFLICT (session_id,chat_jid,message_id) DO NOTHING"
        } else {
            ""
        };
        let sql = format!(
            "INSERT INTO messages \
                (session_id,chat_jid,message_id,sender_jid,from_me,timestamp,msg_type,body_text,payload_json,status) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,COALESCE($10,'received')){tail}"
        );
        let mut c = self.conn()?;
        let mut tx = c.transaction().map_err(pg_err)?;
        let mut count = 0usize;
        for m in rows {
            count += tx
                .execute(
                    sql.as_str(),
                    &[
                        &m.session_id,
                        &m.chat_jid,
                        &m.message_id,
                        &m.sender_jid,
                        &(m.from_me as i64),
                        &m.timestamp,
                        &m.msg_type,
                        &m.body_text,
                        &m.payload_json,
                        &m.status,
                    ],
                )
                .map_err(pg_err)? as usize;
        }
        tx.commit().map_err(pg_err)?;
        Ok(count)
    }

    pub fn prune(
        &self,
        msg_age_cutoff: Option<i64>,
        messages_per_chat: Option<u32>,
        signal_age_cutoff: Option<i64>,
    ) -> rusqlite::Result<(usize, usize, usize)> {
        let mut c = self.conn()?;
        let mut tx = c.transaction().map_err(pg_err)?;
        let mut aged = 0u64;
        let mut over = 0u64;
        let mut sig = 0u64;
        if let Some(cutoff) = msg_age_cutoff {
            aged = tx
                .execute("DELETE FROM messages WHERE timestamp < $1", &[&cutoff])
                .map_err(pg_err)?;
            // Secrets age out with their messages (see SQLite prune).
            tx.execute(
                "DELETE FROM message_secrets WHERE created_at > 0 AND created_at < $1",
                &[&cutoff],
            )
            .map_err(pg_err)?;
        }
        if let Some(keep) = messages_per_chat {
            over = tx
                .execute(
                    "DELETE FROM messages WHERE ctid IN (\
                        SELECT ctid FROM (\
                            SELECT ctid, ROW_NUMBER() OVER (\
                                PARTITION BY session_id, chat_jid \
                                ORDER BY timestamp DESC, message_id DESC) AS rn \
                            FROM messages) t WHERE rn > $1)",
                    &[&(i64::from(keep))],
                )
                .map_err(pg_err)?;
        }
        if let Some(cutoff) = signal_age_cutoff {
            sig = tx
                .execute(
                    "DELETE FROM signal_sessions WHERE updated_at > 0 AND updated_at < $1",
                    &[&cutoff],
                )
                .map_err(pg_err)?;
        }
        tx.commit().map_err(pg_err)?;
        Ok((aged as usize, over as usize, sig as usize))
    }

    pub fn message_set_status(
        &self,
        session_id: &str,
        message_id: &str,
        status: &str,
    ) -> rusqlite::Result<()> {
        self.conn()?
            .execute(
                "UPDATE messages SET status=$1 WHERE session_id=$2 AND message_id=$3",
                &[&status, &session_id, &message_id],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    pub fn message_mark_edited(
        &self,
        session_id: &str,
        message_id: &str,
        new_body: Option<&str>,
    ) -> rusqlite::Result<bool> {
        let n = match new_body {
            Some(b) => self
                .conn()?
                .execute(
                    "UPDATE messages SET body_text=$1, edited=1 \
                     WHERE session_id=$2 AND message_id=$3",
                    &[&b, &session_id, &message_id],
                )
                .map_err(pg_err)?,
            None => self
                .conn()?
                .execute(
                    "UPDATE messages SET edited=1 WHERE session_id=$1 AND message_id=$2",
                    &[&session_id, &message_id],
                )
                .map_err(pg_err)?,
        };
        Ok(n > 0)
    }

    pub fn messages_mark_self_from_me(
        &self,
        session_id: &str,
        own_pn_user: &str,
        own_lid_user: Option<&str>,
    ) -> rusqlite::Result<usize> {
        let pn = format!("{own_pn_user}@s.whatsapp.net");
        let lid = own_lid_user.map(|l| format!("{l}@lid")).unwrap_or_default();
        let n = self
            .conn()?
            .execute(
                "UPDATE messages SET from_me = 1 \
                  WHERE session_id = $1 AND from_me = 0 AND sender_jid IN ($2, $3)",
                &[&session_id, &pn, &lid],
            )
            .map_err(pg_err)?;
        Ok(n as usize)
    }

    /// Postgres twin of `SqliteStore::consolidate_lid_chats`: merge a contact's
    /// `@lid` 1:1 chat into their PN chat via `lid_pn_map`, conflict-guarded.
    pub fn consolidate_lid_chats(&self, session_id: &str) -> rusqlite::Result<usize> {
        let mut conn = self.conn()?;
        let n = conn
            .execute(
                "UPDATE messages SET chat_jid = ( \
                     SELECT m.pn_user || '@s.whatsapp.net' FROM lid_pn_map m \
                      WHERE m.session_id = $1 AND m.lid_user = replace(messages.chat_jid, '@lid', '')) \
                  WHERE session_id = $1 AND chat_jid LIKE '%@lid' \
                    AND EXISTS (SELECT 1 FROM lid_pn_map m WHERE m.session_id = $1 \
                                AND m.lid_user = replace(messages.chat_jid, '@lid', '')) \
                    AND NOT EXISTS (SELECT 1 FROM messages p JOIN lid_pn_map m \
                                      ON m.session_id = $1 AND m.lid_user = replace(messages.chat_jid, '@lid', '') \
                                    WHERE p.session_id = $1 \
                                      AND p.chat_jid = m.pn_user || '@s.whatsapp.net' \
                                      AND p.message_id = messages.message_id)",
                &[&session_id],
            )
            .map_err(pg_err)?;
        conn.execute(
            "DELETE FROM messages WHERE session_id = $1 AND chat_jid LIKE '%@lid' \
               AND EXISTS (SELECT 1 FROM lid_pn_map m WHERE m.session_id = $1 \
                           AND m.lid_user = replace(messages.chat_jid, '@lid', ''))",
            &[&session_id],
        )
        .map_err(pg_err)?;
        conn.execute(
            "UPDATE chats SET jid = ( \
                 SELECT m.pn_user || '@s.whatsapp.net' FROM lid_pn_map m \
                  WHERE m.session_id = $1 AND m.lid_user = replace(chats.jid, '@lid', '')) \
              WHERE session_id = $1 AND jid LIKE '%@lid' \
                AND EXISTS (SELECT 1 FROM lid_pn_map m WHERE m.session_id = $1 \
                            AND m.lid_user = replace(chats.jid, '@lid', '')) \
                AND NOT EXISTS (SELECT 1 FROM chats c2 JOIN lid_pn_map m \
                                  ON m.session_id = $1 AND m.lid_user = replace(chats.jid, '@lid', '') \
                                WHERE c2.session_id = $1 AND c2.jid = m.pn_user || '@s.whatsapp.net')",
            &[&session_id],
        )
        .map_err(pg_err)?;
        // Drop any leftover @lid `chats` row so the merged contact shows once.
        conn.execute(
            "DELETE FROM chats WHERE session_id = $1 AND jid LIKE '%@lid' \
               AND EXISTS (SELECT 1 FROM lid_pn_map m WHERE m.session_id = $1 \
                           AND m.lid_user = replace(chats.jid, '@lid', ''))",
            &[&session_id],
        )
        .map_err(pg_err)?;
        Ok(n as usize)
    }

    // ---- sessions / device keys ----
    pub fn create_session(
        &self,
        s: &NewSession,
        prekeys: &[(u32, &[u8], &[u8])],
    ) -> rusqlite::Result<()> {
        let noise_priv = vault::seal(s.noise_priv);
        let identity_priv = vault::seal(s.identity_priv);
        let spk_priv = vault::seal(s.spk_priv);
        let adv_secret = vault::seal(s.adv_secret);
        let mut c = self.conn()?;
        let mut tx = c.transaction().map_err(pg_err)?;
        tx.execute(
            "INSERT INTO sessions (\
                id,label,status,jid,registration_id, \
                noise_key_priv,noise_key_pub, identity_key_priv,identity_key_pub, \
                signed_prekey_id,signed_prekey_priv,signed_prekey_pub,signed_prekey_sig, \
                adv_secret_key,api_key, created_at,updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)",
            &[
                &s.id,
                &s.label,
                &s.status,
                &s.jid,
                &(i64::from(s.registration_id)),
                &noise_priv,
                &s.noise_pub,
                &identity_priv,
                &s.identity_pub,
                &(i64::from(s.spk_id)),
                &spk_priv,
                &s.spk_pub,
                &s.spk_sig,
                &adv_secret,
                &s.api_key,
                &s.created_at,
                &s.updated_at,
            ],
        )
        .map_err(pg_err)?;
        for (key_id, priv_, pub_) in prekeys {
            let sealed = vault::seal(priv_);
            tx.execute(
                "INSERT INTO prekeys (session_id,key_id,private_key,public_key,uploaded) \
                 VALUES ($1,$2,$3,$4,0)",
                &[&s.id, &(i64::from(*key_id)), &sealed, pub_],
            )
            .map_err(pg_err)?;
        }
        tx.commit().map_err(pg_err)?;
        Ok(())
    }

    pub fn reset_device_keys(
        &self,
        r: &DeviceKeyReset,
        prekeys: &[(u32, &[u8], &[u8])],
    ) -> rusqlite::Result<()> {
        let noise_priv = vault::seal(r.noise_priv);
        let identity_priv = vault::seal(r.identity_priv);
        let spk_priv = vault::seal(r.spk_priv);
        let adv_secret = vault::seal(r.adv_secret);
        let mut c = self.conn()?;
        let mut tx = c.transaction().map_err(pg_err)?;
        tx.execute(
            "UPDATE sessions SET \
                registration_id=$1, \
                noise_key_priv=$2, noise_key_pub=$3, identity_key_priv=$4, identity_key_pub=$5, \
                signed_prekey_id=$6, signed_prekey_priv=$7, signed_prekey_pub=$8, signed_prekey_sig=$9, \
                adv_secret_key=$10, \
                jid=NULL, account_pb=NULL, business_name=NULL, platform=NULL, \
                push_name=NULL, server_token=NULL, client_token=NULL, \
                status='logged_out', updated_at=$11 \
             WHERE id=$12",
            &[
                &(i64::from(r.registration_id)),
                &noise_priv,
                &r.noise_pub,
                &identity_priv,
                &r.identity_pub,
                &(i64::from(r.spk_id)),
                &spk_priv,
                &r.spk_pub,
                &r.spk_sig,
                &adv_secret,
                &r.updated_at,
                &r.id,
            ],
        )
        .map_err(pg_err)?;
        for table in [
            "signal_sessions", "sender_keys", "prekeys",
            "app_state_versions", "app_state_mac_keys", "remote_identities",
        ] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE session_id=$1"),
                &[&r.id],
            )
            .map_err(pg_err)?;
        }
        for (key_id, priv_, pub_) in prekeys {
            let sealed = vault::seal(priv_);
            tx.execute(
                "INSERT INTO prekeys (session_id,key_id,private_key,public_key,uploaded) \
                 VALUES ($1,$2,$3,$4,0)",
                &[&r.id, &(i64::from(*key_id)), &sealed, pub_],
            )
            .map_err(pg_err)?;
        }
        tx.commit().map_err(pg_err)?;
        Ok(())
    }

    pub fn device_keys_load(&self, id: &str) -> rusqlite::Result<Option<DeviceKeyRow>> {
        let row = self
            .conn()?
            .query_opt(
                "SELECT registration_id, noise_key_priv, noise_key_pub, \
                        identity_key_priv, identity_key_pub, signed_prekey_id, \
                        signed_prekey_priv, signed_prekey_pub, signed_prekey_sig, adv_secret_key \
                 FROM sessions WHERE id=$1",
                &[&id],
            )
            .map_err(pg_err)?;
        match row {
            None => Ok(None),
            Some(r) => Ok(Some(DeviceKeyRow {
                registration_id: r.get::<_, i64>(0) as u32,
                noise_priv: unseal(r.get::<_, Vec<u8>>(1))?,
                noise_pub: r.get::<_, Vec<u8>>(2),
                identity_priv: unseal(r.get::<_, Vec<u8>>(3))?,
                identity_pub: r.get::<_, Vec<u8>>(4),
                spk_id: r.get::<_, i64>(5) as u32,
                spk_priv: unseal(r.get::<_, Vec<u8>>(6))?,
                spk_pub: r.get::<_, Vec<u8>>(7),
                spk_sig: r.get::<_, Vec<u8>>(8),
                adv_secret: unseal(r.get::<_, Vec<u8>>(9))?,
            })),
        }
    }

    pub fn device_keys_set_adv_secret(&self, id: &str, adv_secret: &[u8]) -> rusqlite::Result<()> {
        let sealed = vault::seal(adv_secret);
        self.conn()?
            .execute(
                "UPDATE sessions SET adv_secret_key=$1, updated_at=$2 WHERE id=$3",
                &[&sealed, &chrono::Utc::now().timestamp(), &id],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    pub fn sessions_all(&self) -> rusqlite::Result<Vec<SessionRow>> {
        let rows = self
            .conn()?
            .query(
                "SELECT id,label,status,jid,push_name,created_at,updated_at,proxy_url,mark_online FROM sessions",
                &[],
            )
            .map_err(pg_err)?;
        Ok(rows
            .iter()
            .map(|r| SessionRow {
                id: r.get(0),
                label: r.get(1),
                status: r.get(2),
                jid: r.get(3),
                push_name: r.get(4),
                created_at: r.get(5),
                updated_at: r.get(6),
                proxy_url: r.get(7),
                mark_online: r.get::<_, i32>(8) != 0,
            })
            .collect())
    }

    pub fn session_mark_online(&self, id: &str) -> rusqlite::Result<bool> {
        let rows = self
            .conn()?
            .query("SELECT mark_online FROM sessions WHERE id=$1", &[&id])
            .map_err(pg_err)?;
        Ok(rows.first().map(|r| r.get::<_, i32>(0) != 0).unwrap_or(false))
    }

    pub fn session_set_mark_online(&self, id: &str, on: bool) -> rusqlite::Result<()> {
        self.conn()?
            .execute(
                "UPDATE sessions SET mark_online=$1 WHERE id=$2",
                &[&(on as i32), &id],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    pub fn session_delete(&self, id: &str) -> rusqlite::Result<()> {
        self.conn()?
            .execute("DELETE FROM sessions WHERE id=$1", &[&id])
            .map_err(pg_err)?;
        Ok(())
    }

    pub fn session_api_key(&self, id: &str) -> rusqlite::Result<Option<String>> {
        let row = self
            .conn()?
            .query_opt("SELECT api_key FROM sessions WHERE id=$1", &[&id])
            .map_err(pg_err)?;
        Ok(row.and_then(|r| r.get::<_, Option<String>>(0)))
    }

    pub fn session_set_proxy(
        &self,
        id: &str,
        proxy_url: Option<&str>,
        updated_at: i64,
    ) -> rusqlite::Result<()> {
        self.conn()?
            .execute(
                "UPDATE sessions SET proxy_url=$1, updated_at=$2 WHERE id=$3",
                &[&proxy_url, &updated_at, &id],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    /// Rename a session: set (or clear, with `None`) its display label.
    pub fn session_set_label(
        &self,
        id: &str,
        label: Option<&str>,
        updated_at: i64,
    ) -> rusqlite::Result<()> {
        self.conn()?
            .execute(
                "UPDATE sessions SET label=$1, updated_at=$2 WHERE id=$3",
                &[&label, &updated_at, &id],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    pub fn session_proxy(&self, id: &str) -> rusqlite::Result<Option<String>> {
        let row = self
            .conn()?
            .query_opt("SELECT proxy_url FROM sessions WHERE id=$1", &[&id])
            .map_err(pg_err)?;
        Ok(row.and_then(|r| r.get::<_, Option<String>>(0)))
    }

    pub fn session_account_pb(&self, id: &str) -> rusqlite::Result<Option<Vec<u8>>> {
        let row = self
            .conn()?
            .query_opt("SELECT account_pb FROM sessions WHERE id=$1", &[&id])
            .map_err(pg_err)?;
        Ok(row.and_then(|r| r.get::<_, Option<Vec<u8>>>(0)))
    }

    pub fn session_push_name(&self, id: &str) -> rusqlite::Result<Option<String>> {
        let row = self
            .conn()?
            .query_opt("SELECT push_name FROM sessions WHERE id=$1", &[&id])
            .map_err(pg_err)?;
        Ok(row.and_then(|r| r.get::<_, Option<String>>(0)))
    }

    pub fn session_set_push_name(&self, id: &str, name: &str) -> rusqlite::Result<()> {
        self.conn()?
            .execute(
                "UPDATE sessions SET push_name=$1 WHERE id=$2",
                &[&name, &id],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    pub fn session_mark_logged_out(&self, id: &str, updated_at: i64) -> rusqlite::Result<()> {
        self.conn()?
            .execute(
                "UPDATE sessions SET jid=NULL, account_pb=NULL, business_name=NULL, \
                    platform=NULL, push_name=NULL, server_token=NULL, client_token=NULL, \
                    status='logged_out', updated_at=$1 WHERE id=$2",
                &[&updated_at, &id],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    pub fn session_apply_pair_success(
        &self,
        id: &str,
        account_pb: &[u8],
        biz_name: Option<&str>,
        platform: Option<&str>,
        jid: Option<&str>,
        updated_at: i64,
    ) -> rusqlite::Result<()> {
        self.conn()?
            .execute(
                "UPDATE sessions SET account_pb=$1, business_name=$2, platform=$3, jid=$4, \
                    status='connected', updated_at=$5 WHERE id=$6",
                &[&account_pb, &biz_name, &platform, &jid, &updated_at, &id],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    // ---- leases ----
    pub fn lease_acquire(
        &self,
        session_id: &str,
        owner: &str,
        ttl: i64,
        now: i64,
    ) -> rusqlite::Result<bool> {
        let mut c = self.conn()?;
        c.execute(
            "INSERT INTO session_leases (session_id,owner_id,heartbeat_ts,ttl) \
             VALUES ($1,$2,$3,$4) \
             ON CONFLICT (session_id) DO UPDATE SET \
                owner_id=excluded.owner_id, heartbeat_ts=excluded.heartbeat_ts, ttl=excluded.ttl \
             WHERE session_leases.owner_id=excluded.owner_id \
                OR session_leases.heartbeat_ts + session_leases.ttl < excluded.heartbeat_ts",
            &[&session_id, &owner, &now, &ttl],
        )
        .map_err(pg_err)?;
        let row = c
            .query_opt(
                "SELECT owner_id FROM session_leases WHERE session_id=$1",
                &[&session_id],
            )
            .map_err(pg_err)?;
        Ok(row.map(|r| r.get::<_, String>(0)).as_deref() == Some(owner))
    }

    pub fn lease_renew(&self, session_id: &str, owner: &str, now: i64) -> rusqlite::Result<bool> {
        let n = self
            .conn()?
            .execute(
                "UPDATE session_leases SET heartbeat_ts=$1 WHERE session_id=$2 AND owner_id=$3",
                &[&now, &session_id, &owner],
            )
            .map_err(pg_err)?;
        Ok(n > 0)
    }

    pub fn lease_release(&self, session_id: &str, owner: &str) -> rusqlite::Result<()> {
        self.conn()?
            .execute(
                "DELETE FROM session_leases WHERE session_id=$1 AND owner_id=$2",
                &[&session_id, &owner],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    pub fn lease_holder(
        &self,
        session_id: &str,
        now: i64,
    ) -> rusqlite::Result<Option<(String, bool)>> {
        let row = self
            .conn()?
            .query_opt(
                "SELECT owner_id, (heartbeat_ts + ttl < $1) FROM session_leases WHERE session_id=$2",
                &[&now, &session_id],
            )
            .map_err(pg_err)?;
        Ok(row.map(|r| (r.get::<_, String>(0), r.get::<_, bool>(1))))
    }

    // ---- outbound queue ----
    pub fn outbound_queue_drain(&self, session_id: &str) -> rusqlite::Result<Vec<String>> {
        let rows = self
            .conn()?
            .query(
                "SELECT op_json FROM outbound_queue WHERE session_id=$1 \
                 ORDER BY created_at ASC, msg_id ASC",
                &[&session_id],
            )
            .map_err(pg_err)?;
        Ok(rows.iter().map(|r| r.get::<_, String>(0)).collect())
    }

    pub fn outbound_queue_upsert(
        &self,
        session_id: &str,
        msg_id: &str,
        op_json: &str,
        created_at: i64,
    ) -> rusqlite::Result<()> {
        self.conn()?
            .execute(
                "INSERT INTO outbound_queue (session_id,msg_id,op_json,created_at) \
                 VALUES ($1,$2,$3,$4) \
                 ON CONFLICT (session_id,msg_id) DO UPDATE SET \
                    op_json=excluded.op_json, created_at=excluded.created_at",
                &[&session_id, &msg_id, &op_json, &created_at],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    pub fn outbound_queue_delete(&self, session_id: &str, msg_id: &str) -> rusqlite::Result<()> {
        self.conn()?
            .execute(
                "DELETE FROM outbound_queue WHERE session_id=$1 AND msg_id=$2",
                &[&session_id, &msg_id],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    // ---- app state ----
    pub fn app_state_version_get(&self, session_id: &str, name: &str) -> rusqlite::Result<u64> {
        let row = self
            .conn()?
            .query_opt(
                "SELECT version FROM app_state_versions WHERE session_id=$1 AND name=$2",
                &[&session_id, &name],
            )
            .map_err(pg_err)?;
        Ok(row.map(|r| r.get::<_, i64>(0) as u64).unwrap_or(0))
    }

    pub fn app_state_hash_get(
        &self,
        session_id: &str,
        name: &str,
    ) -> rusqlite::Result<Option<Vec<u8>>> {
        let row = self
            .conn()?
            .query_opt(
                "SELECT hash FROM app_state_versions WHERE session_id=$1 AND name=$2",
                &[&session_id, &name],
            )
            .map_err(pg_err)?;
        Ok(row.map(|r| r.get::<_, Vec<u8>>(0)))
    }

    pub fn app_state_version_bump(
        &self,
        session_id: &str,
        name: &str,
        hash: &[u8],
    ) -> rusqlite::Result<()> {
        self.conn()?
            .execute(
                "INSERT INTO app_state_versions (session_id,name,version,hash) \
                 VALUES ($1,$2, COALESCE((SELECT version FROM app_state_versions \
                                           WHERE session_id=$1 AND name=$2),0)+1, $3) \
                 ON CONFLICT (session_id,name) DO UPDATE SET \
                    version=app_state_versions.version+1, hash=excluded.hash",
                &[&session_id, &name, &hash],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    pub fn app_state_version_set(
        &self,
        session_id: &str,
        name: &str,
        version: u64,
        hash: &[u8],
    ) -> rusqlite::Result<()> {
        let v = version as i64;
        self.conn()?
            .execute(
                "INSERT INTO app_state_versions (session_id,name,version,hash) \
                 VALUES ($1,$2,$3,$4) \
                 ON CONFLICT (session_id,name) DO UPDATE SET \
                    version=excluded.version, hash=excluded.hash",
                &[&session_id, &name, &v, &hash],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    pub fn app_state_main_key_save(
        &self,
        session_id: &str,
        key_id: &[u8],
        key_data: &[u8],
    ) -> rusqlite::Result<()> {
        let sealed = vault::seal(key_data);
        self.conn()?
            .execute(
                "INSERT INTO app_state_mac_keys (session_id,key_id,key_data) VALUES ($1,$2,$3) \
                 ON CONFLICT (session_id,key_id) DO UPDATE SET key_data=excluded.key_data",
                &[&session_id, &key_id, &sealed],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    pub fn app_state_main_key_load(
        &self,
        session_id: &str,
        key_id: &[u8],
    ) -> rusqlite::Result<Option<Vec<u8>>> {
        let row = self
            .conn()?
            .query_opt(
                "SELECT key_data FROM app_state_mac_keys WHERE session_id=$1 AND key_id=$2",
                &[&session_id, &key_id],
            )
            .map_err(pg_err)?;
        match row {
            Some(r) => Ok(Some(unseal(r.get::<_, Vec<u8>>(0))?)),
            None => Ok(None),
        }
    }

    // ---- contacts / chats / groups ----
    pub fn contact_upsert(
        &self,
        session_id: &str,
        jid: &str,
        full_name: Option<&str>,
        push_name: Option<&str>,
    ) -> rusqlite::Result<()> {
        self.conn()?
            .execute(
                "INSERT INTO contacts (session_id,jid,full_name,push_name) VALUES ($1,$2,$3,$4) \
                 ON CONFLICT (session_id,jid) DO UPDATE SET \
                    full_name=COALESCE(excluded.full_name, contacts.full_name), \
                    push_name=COALESCE(excluded.push_name, contacts.push_name)",
                &[&session_id, &jid, &full_name, &push_name],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    pub fn chat_set_pinned(
        &self,
        session_id: &str,
        jid: &str,
        pinned: bool,
    ) -> rusqlite::Result<()> {
        self.conn()?
            .execute(
                "INSERT INTO chats (session_id,jid,pinned) VALUES ($1,$2,$3) \
                 ON CONFLICT (session_id,jid) DO UPDATE SET pinned=excluded.pinned",
                &[&session_id, &jid, &(pinned as i64)],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    pub fn chat_set_name(
        &self,
        session_id: &str,
        jid: &str,
        name: Option<&str>,
        is_group: bool,
        last_msg_ts: Option<i64>,
    ) -> rusqlite::Result<()> {
        self.conn()?
            .execute(
                "INSERT INTO chats (session_id,jid,name,is_group,last_msg_ts) VALUES ($1,$2,$3,$4,$5) \
                 ON CONFLICT (session_id,jid) DO UPDATE SET \
                    name=COALESCE(excluded.name, chats.name), \
                    is_group=excluded.is_group, \
                    last_msg_ts=GREATEST(COALESCE(excluded.last_msg_ts,0), COALESCE(chats.last_msg_ts,0))",
                &[&session_id, &jid, &name, &(is_group as i64), &last_msg_ts],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    pub fn chat_set_archived(
        &self,
        session_id: &str,
        jid: &str,
        archived: bool,
    ) -> rusqlite::Result<()> {
        self.conn()?
            .execute(
                "INSERT INTO chats (session_id,jid,archived) VALUES ($1,$2,$3) \
                 ON CONFLICT (session_id,jid) DO UPDATE SET archived=excluded.archived",
                &[&session_id, &jid, &(archived as i64)],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    pub fn chat_set_muted(
        &self,
        session_id: &str,
        jid: &str,
        until: Option<i64>,
    ) -> rusqlite::Result<()> {
        self.conn()?
            .execute(
                "INSERT INTO chats (session_id,jid,muted_until) VALUES ($1,$2,$3) \
                 ON CONFLICT (session_id,jid) DO UPDATE SET muted_until=excluded.muted_until",
                &[&session_id, &jid, &until],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    pub fn group_persist(
        &self,
        session_id: &str,
        jid: &str,
        subject: Option<&str>,
        creator: Option<&str>,
        creation_ts: Option<i64>,
        participants: &[(&str, bool, bool)],
    ) -> rusqlite::Result<()> {
        let mut c = self.conn()?;
        let mut tx = c.transaction().map_err(pg_err)?;
        tx.execute(
            "INSERT INTO groups (session_id,jid,subject,creator,creation_ts) VALUES ($1,$2,$3,$4,$5) \
             ON CONFLICT (session_id,jid) DO UPDATE SET \
                subject=excluded.subject, creator=excluded.creator, creation_ts=excluded.creation_ts",
            &[&session_id, &jid, &subject, &creator, &creation_ts],
        )
        .map_err(pg_err)?;
        tx.execute(
            "DELETE FROM group_participants WHERE session_id=$1 AND group_jid=$2",
            &[&session_id, &jid],
        )
        .map_err(pg_err)?;
        for (user_jid, is_admin, is_super) in participants {
            tx.execute(
                "INSERT INTO group_participants (session_id,group_jid,user_jid,is_admin,is_super) \
                 VALUES ($1,$2,$3,$4,$5)",
                &[&session_id, &jid, user_jid, &(*is_admin as i64), &(*is_super as i64)],
            )
            .map_err(pg_err)?;
        }
        tx.commit().map_err(pg_err)?;
        Ok(())
    }

    // ---- read/list (API surface) ----
    #[allow(clippy::too_many_arguments)]
    pub fn message_insert_media(
        &self,
        session_id: &str,
        chat_jid: &str,
        message_id: &str,
        sender_jid: &str,
        timestamp: i64,
        msg_type: &str,
        body_text: Option<&str>,
        payload_json: &str,
        media_path: Option<&str>,
    ) -> rusqlite::Result<()> {
        self.conn()?
            .execute(
                "INSERT INTO messages \
                    (session_id,chat_jid,message_id,sender_jid,from_me,timestamp,msg_type,body_text,payload_json,media_path,status) \
                 VALUES ($1,$2,$3,$4,1,$5,$6,$7,$8,$9,'queued')",
                &[
                    &session_id, &chat_jid, &message_id, &sender_jid, &timestamp, &msg_type,
                    &body_text, &payload_json, &media_path,
                ],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    pub fn message_set_media_path(
        &self,
        session_id: &str,
        chat_jid: &str,
        message_id: &str,
        media_path: &str,
    ) -> rusqlite::Result<()> {
        self.conn()?
            .execute(
                "UPDATE messages SET media_path=$1 \
                 WHERE session_id=$2 AND chat_jid=$3 AND message_id=$4",
                &[&media_path, &session_id, &chat_jid, &message_id],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    pub fn message_media_lookup(
        &self,
        session_id: &str,
        chat_jid: &str,
        message_id: &str,
    ) -> rusqlite::Result<Option<(Option<String>, String, String)>> {
        let row = self
            .conn()?
            .query_opt(
                "SELECT media_path, msg_type, payload_json FROM messages \
                 WHERE session_id=$1 AND chat_jid=$2 AND message_id=$3",
                &[&session_id, &chat_jid, &message_id],
            )
            .map_err(pg_err)?;
        Ok(row.map(|r| (r.get(0), r.get(1), r.get(2))))
    }

    pub fn messages_list(
        &self,
        session_id: &str,
        chat: Option<&str>,
        needle: Option<&str>,
        before: i64,
        limit: u32,
    ) -> rusqlite::Result<Vec<MessageListRow>> {
        let mut sql = String::from(
            "SELECT chat_jid,message_id,sender_jid,from_me,timestamp,msg_type,body_text,payload_json,edited \
             FROM messages WHERE session_id=$1 AND timestamp < $2",
        );
        let mut params: Vec<&(dyn postgres::types::ToSql + Sync)> = vec![&session_id, &before];
        if let Some(c) = &chat {
            params.push(c);
            sql.push_str(&format!(" AND chat_jid=${}", params.len()));
        }
        // Ranked full-text path: match the generated tsvector and order by
        // relevance (best first) rather than recency. websearch_to_tsquery
        // tolerates arbitrary user input, so no manual sanitization is needed.
        if let Some(n) = &needle {
            params.push(n);
            let qi = params.len();
            sql.push_str(&format!(
                " AND body_tsv @@ websearch_to_tsquery('simple', ${qi}) \
                  ORDER BY ts_rank(body_tsv, websearch_to_tsquery('simple', ${qi})) DESC, \
                  timestamp DESC LIMIT "
            ));
        } else {
            sql.push_str(" ORDER BY timestamp DESC LIMIT ");
        }
        sql.push_str(&limit.to_string());
        let rows = self.conn()?.query(sql.as_str(), &params).map_err(pg_err)?;
        Ok(rows
            .iter()
            .map(pg_row_to_msg_list)
            .collect())
    }

    pub fn message_context(
        &self,
        session_id: &str,
        chat: &str,
        msg_id: &str,
        before: u32,
        after: u32,
    ) -> rusqlite::Result<Vec<MessageListRow>> {
        let ts: Option<i64> = self
            .conn()?
            .query_opt(
                "SELECT timestamp FROM messages \
                 WHERE session_id=$1 AND chat_jid=$2 AND message_id=$3",
                &[&session_id, &chat, &msg_id],
            )
            .map_err(pg_err)?
            .map(|r| r.get::<_, i64>(0));
        let Some(ts) = ts else { return Ok(vec![]) };
        const COLS: &str =
            "chat_jid,message_id,sender_jid,from_me,timestamp,msg_type,body_text,payload_json,edited";
        let older_sql = format!(
            "SELECT {COLS} FROM messages WHERE session_id=$1 AND chat_jid=$2 \
             AND timestamp <= $3 ORDER BY timestamp DESC, message_id DESC LIMIT {}",
            before as u64 + 1
        );
        let mut older: Vec<MessageListRow> = self
            .conn()?
            .query(older_sql.as_str(), &[&session_id, &chat, &ts])
            .map_err(pg_err)?
            .iter()
            .map(pg_row_to_msg_list)
            .collect();
        older.reverse();
        let newer_sql = format!(
            "SELECT {COLS} FROM messages WHERE session_id=$1 AND chat_jid=$2 \
             AND timestamp > $3 ORDER BY timestamp ASC, message_id ASC LIMIT {after}"
        );
        let newer: Vec<MessageListRow> = self
            .conn()?
            .query(newer_sql.as_str(), &[&session_id, &chat, &ts])
            .map_err(pg_err)?
            .iter()
            .map(pg_row_to_msg_list)
            .collect();
        older.extend(newer);
        Ok(older)
    }

    pub fn message_oldest_for_chat(
        &self,
        session_id: &str,
        chat: &str,
    ) -> rusqlite::Result<Option<(String, bool, i64)>> {
        let row = self
            .conn()?
            .query_opt(
                "SELECT message_id, from_me, timestamp FROM messages \
                 WHERE session_id=$1 AND chat_jid=$2 \
                 ORDER BY timestamp ASC, message_id ASC LIMIT 1",
                &[&session_id, &chat],
            )
            .map_err(pg_err)?;
        Ok(row.map(|r| {
            (
                r.get::<_, String>(0),
                r.get::<_, i64>(1) != 0,
                r.get::<_, i64>(2),
            )
        }))
    }

    pub fn contacts_list(&self, session_id: &str) -> rusqlite::Result<Vec<ContactRow>> {
        // Collapse each contact's `@lid` + PN rows into one canonical (PN) row
        // via `lid_pn_map`; see the SQLite twin for the rationale.
        let rows = self
            .conn()?
            .query(
                "SELECT canon AS jid, MAX(full_name), MAX(push_name), MAX(business_name) \
                   FROM ( \
                     SELECT CASE \
                              WHEN c.jid LIKE '%@lid' AND m.pn_user IS NOT NULL \
                              THEN m.pn_user || '@s.whatsapp.net' ELSE c.jid END AS canon, \
                            c.full_name, c.push_name, c.business_name \
                       FROM contacts c \
                       LEFT JOIN lid_pn_map m \
                         ON m.session_id=$1 AND m.lid_user = replace(c.jid, '@lid', '') \
                      WHERE c.session_id=$1 \
                   ) sub GROUP BY canon ORDER BY canon",
                &[&session_id],
            )
            .map_err(pg_err)?;
        Ok(rows
            .iter()
            .map(|r| ContactRow {
                jid: r.get(0),
                full_name: r.get(1),
                push_name: r.get(2),
                business_name: r.get(3),
            })
            .collect())
    }

    pub fn chats_list(&self, session_id: &str) -> rusqlite::Result<Vec<ChatRow>> {
        let rows = self
            .conn()?
            .query(
                "SELECT conv.jid, \
                        COALESCE(c.name, ct.full_name, ct.push_name, ct.first_name) AS name, \
                        CASE WHEN conv.jid LIKE '%@g.us' THEN 1 ELSE COALESCE(c.is_group, 0) END AS is_group, \
                        conv.last_msg_ts, \
                        COALESCE(c.archived, 0) AS archived, \
                        COALESCE(c.pinned, 0) AS pinned, \
                        c.muted_until \
                   FROM ( \
                     SELECT chat_jid AS jid, MAX(timestamp) AS last_msg_ts \
                       FROM messages WHERE session_id=$1 GROUP BY chat_jid \
                     UNION \
                     SELECT jid, last_msg_ts FROM chats \
                       WHERE session_id=$1 \
                         AND jid NOT IN (SELECT DISTINCT chat_jid FROM messages WHERE session_id=$1) \
                   ) conv \
                   LEFT JOIN chats c     ON c.session_id=$1 AND c.jid=conv.jid \
                   LEFT JOIN contacts ct ON ct.session_id=$1 AND ct.jid=conv.jid \
                   LEFT JOIN lid_pn_map lmp ON lmp.session_id=$1 AND lmp.pn_user = substring(conv.jid from '^[^.:@]+') \
                   LEFT JOIN contacts ctl   ON ctl.session_id=$1 AND ctl.jid = lmp.lid_user || '@lid' \
                   LEFT JOIN lid_pn_map lml ON lml.session_id=$1 AND lml.lid_user = substring(conv.jid from '^[^.:@]+') \
                   LEFT JOIN contacts ctp   ON ctp.session_id=$1 AND ctp.jid = lml.pn_user || '@s.whatsapp.net' \
                  ORDER BY COALESCE(conv.last_msg_ts,0) DESC",
                &[&session_id],
            )
            .map_err(pg_err)?;
        Ok(rows
            .iter()
            .map(|r| ChatRow {
                jid: r.get(0),
                name: r.get(1),
                is_group: r.get::<_, i64>(2) != 0,
                last_msg_ts: r.get(3),
                archived: r.get::<_, i64>(4) != 0,
                pinned: r.get::<_, i64>(5) != 0,
                muted_until: r.get(6),
            })
            .collect())
    }


    pub fn pns_without_lid_mapping(
        &self,
        session_id: &str,
        limit: u32,
    ) -> rusqlite::Result<Vec<String>> {
        let rows = self
            .conn()?
            .query(
                "SELECT DISTINCT u.jid FROM ( \
                     SELECT chat_jid AS jid FROM messages \
                      WHERE session_id=$1 AND chat_jid LIKE '%@s.whatsapp.net' \
                     UNION \
                     SELECT jid FROM contacts \
                      WHERE session_id=$1 AND jid LIKE '%@s.whatsapp.net') u \
                  WHERE NOT EXISTS ( \
                      SELECT 1 FROM lid_pn_map lm \
                       WHERE lm.session_id=$1 \
                         AND lm.pn_user = substring(u.jid from '^[^.:@]+')) \
                  LIMIT $2",
                &[&session_id, &(limit as i64)],
            )
            .map_err(pg_err)?;
        Ok(rows.iter().map(|r| r.get(0)).collect())
    }

    pub fn groups_list(&self, session_id: &str) -> rusqlite::Result<Vec<GroupRow>> {
        let rows = self
            .conn()?
            .query(
                "SELECT jid,subject,creator,creation_ts FROM groups \
                 WHERE session_id=$1 ORDER BY jid",
                &[&session_id],
            )
            .map_err(pg_err)?;
        Ok(rows
            .iter()
            .map(|r| GroupRow {
                jid: r.get(0),
                subject: r.get(1),
                creator: r.get(2),
                creation_ts: r.get(3),
            })
            .collect())
    }

}

// Egress-target storage (Postgres). See the SqliteStore counterpart for why this
// is a separate `#[allow(dead_code)]` impl (store layer precedes its callers).
#[allow(dead_code)]
impl PgStore {
    pub fn egress_set(&self, t: &EgressTarget) -> rusqlite::Result<()> {
        self.conn()?
            .execute(
                "INSERT INTO egress_targets \
                    (session_id, kind, enabled, events, secret, config, updated_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7) \
                 ON CONFLICT (session_id, kind) DO UPDATE SET \
                    enabled=excluded.enabled, events=excluded.events, \
                    secret=excluded.secret, config=excluded.config, \
                    updated_at=excluded.updated_at",
                &[
                    &t.session_id,
                    &t.kind,
                    &t.enabled,
                    &t.events,
                    &t.secret,
                    &t.config,
                    &t.updated_at,
                ],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    pub fn egress_get(
        &self,
        session_id: &str,
        kind: &str,
    ) -> rusqlite::Result<Option<EgressTarget>> {
        let row = self
            .conn()?
            .query_opt(
                "SELECT session_id, kind, enabled, events, secret, config, updated_at \
                   FROM egress_targets WHERE session_id=$1 AND kind=$2",
                &[&session_id, &kind],
            )
            .map_err(pg_err)?;
        Ok(row.as_ref().map(pg_row_to_egress))
    }

    pub fn egress_list_for_session(
        &self,
        session_id: &str,
    ) -> rusqlite::Result<Vec<EgressTarget>> {
        let rows = self
            .conn()?
            .query(
                "SELECT session_id, kind, enabled, events, secret, config, updated_at \
                   FROM egress_targets WHERE session_id=$1 ORDER BY kind",
                &[&session_id],
            )
            .map_err(pg_err)?;
        Ok(rows.iter().map(pg_row_to_egress).collect())
    }

    pub fn egress_list_all(&self) -> rusqlite::Result<Vec<EgressTarget>> {
        let rows = self
            .conn()?
            .query(
                "SELECT session_id, kind, enabled, events, secret, config, updated_at \
                   FROM egress_targets ORDER BY session_id, kind",
                &[],
            )
            .map_err(pg_err)?;
        Ok(rows.iter().map(pg_row_to_egress).collect())
    }

    pub fn egress_delete(&self, session_id: &str, kind: &str) -> rusqlite::Result<()> {
        self.conn()?
            .execute(
                "DELETE FROM egress_targets WHERE session_id=$1 AND kind=$2",
                &[&session_id, &kind],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    // ---- event log (dashboard Logs history) ----

    pub fn event_log_insert(
        &self,
        session_id: &str,
        ts: i64,
        event_type: &str,
        payload_json: &str,
    ) -> rusqlite::Result<()> {
        self.conn()?
            .execute(
                "INSERT INTO event_log (session_id, ts, event_type, payload_json) \
                 VALUES ($1, $2, $3, $4)",
                &[&session_id, &ts, &event_type, &payload_json],
            )
            .map_err(pg_err)?;
        Ok(())
    }

    pub fn event_log_list(
        &self,
        session_id: &str,
        before_id: i64,
        type_filter: Option<&str>,
        limit: u32,
    ) -> rusqlite::Result<Vec<EventLogRow>> {
        let mut sql = String::from(
            "SELECT id, ts, event_type, payload_json FROM event_log \
               WHERE session_id = $1 AND id < $2",
        );
        if type_filter.is_some() {
            sql.push_str(" AND event_type = $3");
        }
        sql.push_str(" ORDER BY id DESC LIMIT ");
        sql.push_str(&limit.to_string());

        let mut conn = self.conn()?;
        let rows = match type_filter {
            Some(t) => conn.query(sql.as_str(), &[&session_id, &before_id, &t]),
            None => conn.query(sql.as_str(), &[&session_id, &before_id]),
        }
        .map_err(pg_err)?;
        Ok(rows
            .iter()
            .map(|r| EventLogRow {
                id: r.get(0),
                ts: r.get(1),
                event_type: r.get(2),
                payload_json: r.get(3),
            })
            .collect())
    }

    pub fn event_log_prune(
        &self,
        session_id: &str,
        keep_max: i64,
        age_cutoff_ms: i64,
    ) -> rusqlite::Result<usize> {
        let n = self
            .conn()?
            .execute(
                "DELETE FROM event_log \
                  WHERE session_id = $1 \
                    AND (ts < $2 \
                         OR id NOT IN ( \
                             SELECT id FROM event_log WHERE session_id = $1 \
                              ORDER BY id DESC LIMIT $3))",
                &[&session_id, &age_cutoff_ms, &keep_max],
            )
            .map_err(pg_err)?;
        Ok(n as usize)
    }

    pub fn metrics_sample_insert_batch(
        &self,
        rows: &[(&str, i64, f64)],
    ) -> rusqlite::Result<usize> {
        let mut c = self.conn()?;
        let mut tx = c.transaction().map_err(pg_err)?;
        let mut n = 0usize;
        for (name, ts, value) in rows {
            n += tx
                .execute(
                    "INSERT INTO metrics_samples (name, ts, value) VALUES ($1, $2, $3) \
                     ON CONFLICT (name, ts) DO NOTHING",
                    &[name, ts, value],
                )
                .map_err(pg_err)? as usize;
        }
        tx.commit().map_err(pg_err)?;
        Ok(n)
    }

    pub fn metrics_history(
        &self,
        name: &str,
        since_ts: i64,
        limit: u32,
    ) -> rusqlite::Result<Vec<MetricPoint>> {
        let sql = format!(
            "SELECT ts, value FROM metrics_samples WHERE name = $1 AND ts >= $2 \
             ORDER BY ts DESC LIMIT {limit}"
        );
        let rows = self
            .conn()?
            .query(sql.as_str(), &[&name, &since_ts])
            .map_err(pg_err)?;
        let mut pts: Vec<MetricPoint> = rows
            .iter()
            .map(|r| MetricPoint {
                ts: r.get(0),
                value: r.get(1),
            })
            .collect();
        pts.reverse(); // DESC fetch → ASC for charting
        Ok(pts)
    }

    pub fn metrics_names(&self) -> rusqlite::Result<Vec<String>> {
        let rows = self
            .conn()?
            .query(
                "SELECT DISTINCT name FROM metrics_samples ORDER BY name",
                &[],
            )
            .map_err(pg_err)?;
        Ok(rows.iter().map(|r| r.get(0)).collect())
    }

    pub fn metrics_prune(&self, age_cutoff: i64) -> rusqlite::Result<usize> {
        let n = self
            .conn()?
            .execute("DELETE FROM metrics_samples WHERE ts < $1", &[&age_cutoff])
            .map_err(pg_err)?;
        Ok(n as usize)
    }

    pub fn log_ring_insert_batch(
        &self,
        rows: &[(i64, i32, &str, &str, &str)],
    ) -> rusqlite::Result<usize> {
        let mut c = self.conn()?;
        let mut tx = c.transaction().map_err(pg_err)?;
        let mut n = 0usize;
        for (ts, sev, level, target, message) in rows {
            n += tx
                .execute(
                    "INSERT INTO log_ring (ts, sev, level, target, message) \
                     VALUES ($1, $2, $3, $4, $5)",
                    &[ts, sev, level, target, message],
                )
                .map_err(pg_err)? as usize;
        }
        tx.commit().map_err(pg_err)?;
        Ok(n)
    }

    pub fn log_ring_query(
        &self,
        min_sev: i32,
        before_id: i64,
        limit: u32,
    ) -> rusqlite::Result<Vec<LogRow>> {
        let sql = format!(
            "SELECT id, ts, level, target, message FROM log_ring \
               WHERE sev >= $1 AND id < $2 ORDER BY id DESC LIMIT {limit}"
        );
        let rows = self
            .conn()?
            .query(sql.as_str(), &[&min_sev, &before_id])
            .map_err(pg_err)?;
        Ok(rows
            .iter()
            .map(|r| LogRow {
                id: r.get(0),
                ts: r.get(1),
                level: r.get(2),
                target: r.get(3),
                message: r.get(4),
            })
            .collect())
    }

    pub fn log_ring_prune(
        &self,
        keep_max: i64,
        age_cutoff_ms: i64,
    ) -> rusqlite::Result<usize> {
        let n = self
            .conn()?
            .execute(
                "DELETE FROM log_ring \
                  WHERE ts < $1 \
                     OR id NOT IN (SELECT id FROM log_ring ORDER BY id DESC LIMIT $2)",
                &[&age_cutoff_ms, &keep_max],
            )
            .map_err(pg_err)?;
        Ok(n as usize)
    }
}

/// Map a Postgres `messages` row (canonical column order) to `MessageListRow`.
fn pg_row_to_msg_list(r: &postgres::Row) -> MessageListRow {
    MessageListRow {
        chat_jid: r.get(0),
        message_id: r.get(1),
        sender_jid: r.get(2),
        from_me: r.get::<_, i64>(3) != 0,
        timestamp: r.get(4),
        msg_type: r.get(5),
        body_text: r.get(6),
        // Column 7 is `payload_json`; pull the reply quote out of it (if present).
        quoted: parse_quoted(&r.get::<_, String>(7)),
        edited: r.get::<_, i64>(8) != 0,
    }
}

fn pg_row_to_egress(r: &postgres::Row) -> EgressTarget {
    EgressTarget {
        session_id: r.get(0),
        kind: r.get(1),
        enabled: r.get(2),
        events: r.get(3),
        secret: r.get(4),
        config: r.get(5),
        updated_at: r.get(6),
    }
}

/// A session's restore-time metadata row (status is the raw stored string).
pub struct SessionRow {
    pub id: String,
    pub label: Option<String>,
    pub status: String,
    pub jid: Option<String>,
    pub push_name: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub proxy_url: Option<String>,
    pub mark_online: bool,
}

/// All columns needed to insert a fresh session row (borrowed; the byte slices
/// are the long-term key material). Mirrors the `sessions` create-time schema.
pub struct NewSession<'a> {
    pub id: &'a str,
    pub label: Option<&'a str>,
    pub status: &'a str,
    pub jid: Option<&'a str>,
    pub registration_id: u32,
    pub noise_priv: &'a [u8],
    pub noise_pub: &'a [u8],
    pub identity_priv: &'a [u8],
    pub identity_pub: &'a [u8],
    pub spk_id: u32,
    pub spk_priv: &'a [u8],
    pub spk_pub: &'a [u8],
    pub spk_sig: &'a [u8],
    pub adv_secret: &'a [u8],
    pub api_key: &'a str,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Fresh device keys for a `reset_device_keys` (logout `fresh=true`). Carries
/// the same key material as a `NewSession` but UPDATES an existing row in place
/// — preserving id/label/api_key/proxy/webhooks — while clearing the paired
/// state and stale crypto so the next pairing is a genuinely new device.
pub struct DeviceKeyReset<'a> {
    pub id: &'a str,
    pub registration_id: u32,
    pub noise_priv: &'a [u8],
    pub noise_pub: &'a [u8],
    pub identity_priv: &'a [u8],
    pub identity_pub: &'a [u8],
    pub spk_id: u32,
    pub spk_priv: &'a [u8],
    pub spk_pub: &'a [u8],
    pub spk_sig: &'a [u8],
    pub adv_secret: &'a [u8],
    pub updated_at: i64,
}

/// The device-key columns as stored (raw bytes). `session.rs` maps this into
/// the crypto `DeviceKeys`; keys-at-rest unsealing happens at that boundary.
pub struct DeviceKeyRow {
    pub registration_id: u32,
    pub noise_priv: Vec<u8>,
    pub noise_pub: Vec<u8>,
    pub identity_priv: Vec<u8>,
    pub identity_pub: Vec<u8>,
    pub spk_id: u32,
    pub spk_priv: Vec<u8>,
    pub spk_pub: Vec<u8>,
    pub spk_sig: Vec<u8>,
    pub adv_secret: Vec<u8>,
}

/// A message row to persist. Borrowed view so callers don't allocate; `status`
/// of `None` defers to the column default. `from_me` is the API-neutral bool.
pub struct NewMessage<'a> {
    pub session_id: &'a str,
    pub chat_jid: &'a str,
    pub message_id: &'a str,
    pub sender_jid: &'a str,
    pub from_me: bool,
    pub timestamp: i64,
    pub msg_type: &'a str,
    pub body_text: Option<&'a str>,
    pub payload_json: &'a str,
    pub status: Option<&'a str>,
}

fn migrations() -> Migrations<'static> {
    Migrations::new(vec![
        M::up(include_str!("../migrations/0001_initial.sql")),
        M::up(include_str!("../migrations/0002_status_and_outbound_queue.sql")),
        M::up(include_str!("../migrations/0003_proxy_url.sql")),
        M::up(include_str!("../migrations/0004_api_key.sql")),
        M::up(include_str!("../migrations/0005_signal_session_updated_at.sql")),
        M::up(include_str!("../migrations/0006_session_leases.sql")),
        M::up(include_str!("../migrations/0007_egress.sql")),
        M::up(include_str!("../migrations/0008_lid_pn_map.sql")),
        M::up(include_str!("../migrations/0009_canonicalize_lid_pn.sql")),
        M::up(include_str!("../migrations/0010_purge_protocol_message_rows.sql")),
        M::up(include_str!("../migrations/0011_event_log.sql")),
        M::up(include_str!("../migrations/0012_mark_online.sql")),
        M::up(include_str!("../migrations/0013_metrics_samples.sql")),
        M::up(include_str!("../migrations/0014_log_ring.sql")),
        M::up(include_str!("../migrations/0015_messages_fts.sql")),
        M::up(include_str!("../migrations/0016_message_secrets.sql")),
        M::up(include_str!("../migrations/0017_messages_edited.sql")),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Seed a minimal session row so FK-bearing tables (egress_targets, …) accept
    /// inserts. Returns the session id.
    fn seed_session(store: &Store, id: &str) {
        store
            .create_session(
                &NewSession {
                    id,
                    label: None,
                    status: "pending",
                    jid: None,
                    registration_id: 1,
                    noise_priv: &[1u8; 32],
                    noise_pub: &[2u8; 32],
                    identity_priv: &[3u8; 32],
                    identity_pub: &[4u8; 32],
                    spk_id: 1,
                    spk_priv: &[5u8; 32],
                    spk_pub: &[6u8; 32],
                    spk_sig: &[0u8; 64],
                    adv_secret: &[7u8; 32],
                    api_key: "k",
                    created_at: 1,
                    updated_at: 1,
                },
                &[(1, &[9u8; 32], &[8u8; 32])],
            )
            .unwrap();
    }

    #[test]
    fn app_state_version_set_writes_absolute_version() {
        let store = Store::open(":memory:").unwrap();
        seed_session(&store, "s1");
        // bump → version 1
        store.app_state_version_bump("s1", "critical_block", &[0u8; 128]).unwrap();
        assert_eq!(store.app_state_version_get("s1", "critical_block").unwrap(), 1);
        // set → absolute (snapshot version), replacing the incremented one
        store
            .app_state_version_set("s1", "critical_block", 143, &[7u8; 128])
            .unwrap();
        assert_eq!(
            store.app_state_version_get("s1", "critical_block").unwrap(),
            143
        );
        assert_eq!(
            store.app_state_hash_get("s1", "critical_block").unwrap().unwrap(),
            vec![7u8; 128]
        );
    }

    #[test]
    fn message_context_returns_window_around_target() {
        let store = Store::open(":memory:").unwrap();
        seed_session(&store, "s1");
        for ts in 1..=10i64 {
            store
                .message_insert(
                    &NewMessage {
                        session_id: "s1",
                        chat_jid: "c@s",
                        message_id: &format!("m{ts}"),
                        sender_jid: "x@s",
                        from_me: false,
                        timestamp: ts,
                        msg_type: "text",
                        body_text: Some("hi"),
                        payload_json: "{}",
                        status: None,
                    },
                    true,
                )
                .unwrap();
        }
        // 2 before + target(m5) + 3 after → m3..m8 in chronological order.
        let ctx = store.message_context("s1", "c@s", "m5", 2, 3).unwrap();
        let ids: Vec<&str> = ctx.iter().map(|r| r.message_id.as_str()).collect();
        assert_eq!(ids, vec!["m3", "m4", "m5", "m6", "m7", "m8"]);
        // Clamped at the head: target m1 with 5 before → m1..m4, no underflow.
        let head = store.message_context("s1", "c@s", "m1", 5, 3).unwrap();
        assert_eq!(head.first().unwrap().message_id, "m1");
        assert_eq!(head.last().unwrap().message_id, "m4");
        // Unknown id → empty.
        assert!(store
            .message_context("s1", "c@s", "nope", 5, 5)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn messages_list_ranked_full_text_search() {
        let store = Store::open(":memory:").unwrap();
        seed_session(&store, "s1");
        let mut ts = 0i64;
        let mut insert = |id: &str, body: &str| {
            ts += 1;
            store
                .message_insert(
                    &NewMessage {
                        session_id: "s1",
                        chat_jid: "c@s",
                        message_id: id,
                        sender_jid: "x@s",
                        from_me: false,
                        timestamp: ts,
                        msg_type: "text",
                        body_text: Some(body),
                        payload_json: "{}",
                        status: None,
                    },
                    true,
                )
                .unwrap();
        };
        insert("m1", "What do you think about Putin and the war?");
        insert("m2", "I prefer talking about football honestly");
        insert("m3", "PUTIN gave a speech today"); // case-insensitive match
        insert("m4", "Vamos falar sobre o José na reunião"); // accent: query "jose"

        // Single term, case-insensitive, ranked: both Putin messages, no football.
        let hits = store.messages_list("s1", None, Some("putin"), i64::MAX, 10).unwrap();
        let ids: Vec<&str> = hits.iter().map(|r| r.message_id.as_str()).collect();
        assert_eq!(ids.len(), 2, "both Putin messages match, ignoring case");
        assert!(ids.contains(&"m1") && ids.contains(&"m3"));
        assert!(!ids.contains(&"m2"));

        // Accent-insensitive: ascii "jose" matches "José".
        let jose = store.messages_list("s1", None, Some("jose"), i64::MAX, 10).unwrap();
        assert_eq!(jose.len(), 1);
        assert_eq!(jose[0].message_id, "m4");

        // Multi-term is implicit-AND: both words must appear.
        let both = store.messages_list("s1", None, Some("putin war"), i64::MAX, 10).unwrap();
        assert_eq!(both.len(), 1);
        assert_eq!(both[0].message_id, "m1");

        // No match → empty; punctuation-only query → empty (no FTS syntax error).
        assert!(store.messages_list("s1", None, Some("nonexistent"), i64::MAX, 10).unwrap().is_empty());
        assert!(store.messages_list("s1", None, Some("???"), i64::MAX, 10).unwrap().is_empty());
        assert!(store.messages_list("s1", None, Some("who's there?"), i64::MAX, 10).unwrap().is_empty());

        // The delete trigger keeps the index in sync: prune m1 (ts==1) and it
        // stops matching, while m3 still does.
        let (aged, _, _) = store.prune(Some(2), None, None).unwrap();
        assert_eq!(aged, 1, "only m1 is older than the cutoff");
        let after = store.messages_list("s1", None, Some("putin"), i64::MAX, 10).unwrap();
        assert_eq!(after.len(), 1, "m1 removed from the FTS index by the delete trigger");
        assert_eq!(after[0].message_id, "m3");
    }

    #[test]
    fn chats_list_derives_conversations_from_messages() {
        let store = Store::open(":memory:").unwrap();
        seed_session(&store, "s1");

        // No messages, no app-state rows → empty conversation list.
        assert!(store.chats_list("s1").unwrap().is_empty());

        let msg = |chat: &str, ts: i64| {
            store
                .message_insert(
                    &NewMessage {
                        session_id: "s1",
                        chat_jid: chat,
                        message_id: &format!("m{ts}"),
                        sender_jid: chat,
                        from_me: false,
                        timestamp: ts,
                        msg_type: "text",
                        body_text: Some("hi"),
                        payload_json: "{}",
                        status: None,
                    },
                    true,
                )
                .unwrap();
        };
        // Two real conversations — a 1:1 and a group — surface even though nothing
        // ever wrote to the `chats` table.
        msg("a@s.whatsapp.net", 100);
        msg("b@g.us", 200);

        let chats = store.chats_list("s1").unwrap();
        assert_eq!(chats.len(), 2);
        // Ordered by last_msg_ts DESC: the group (ts 200) comes first.
        assert_eq!(chats[0].jid, "b@g.us");
        assert!(chats[0].is_group, "@g.us jid is detected as a group");
        assert_eq!(chats[0].last_msg_ts, Some(200));
        assert_eq!(chats[1].jid, "a@s.whatsapp.net");
        assert!(!chats[1].is_group);

        // Names resolve from the contacts table.
        store
            .contact_upsert("s1", "a@s.whatsapp.net", Some("Alice"), None)
            .unwrap();
        let chats = store.chats_list("s1").unwrap();
        assert_eq!(chats.iter().find(|c| c.jid == "a@s.whatsapp.net").unwrap().name.as_deref(), Some("Alice"));

        // A metadata-only chat (pinned before any message arrived) still appears,
        // carrying its pinned flag.
        store.chat_set_pinned("s1", "c@s.whatsapp.net", true).unwrap();
        let chats = store.chats_list("s1").unwrap();
        assert_eq!(chats.len(), 3);
        let c = chats.iter().find(|c| c.jid == "c@s.whatsapp.net").unwrap();
        assert!(c.pinned);
        assert_eq!(c.last_msg_ts, None);
    }

    #[test]
    fn consolidate_lid_chats_merges_lid_into_pn() {
        let store = Store::open(":memory:").unwrap();
        seed_session(&store, "s1");
        let msg = |chat: &str, id: &str, ts: i64| {
            store
                .message_insert(
                    &NewMessage {
                        session_id: "s1",
                        chat_jid: chat,
                        message_id: id,
                        sender_jid: chat,
                        from_me: false,
                        timestamp: ts,
                        msg_type: "text",
                        body_text: Some("hi"),
                        payload_json: "{}",
                        status: None,
                    },
                    true,
                )
                .unwrap();
        };
        // Henry appears twice: under his LID (group-derived) and his phone number.
        msg("64000000000001@lid", "L1", 100);
        msg("64000000000001@lid", "L2", 110);
        msg("5511990000001@s.whatsapp.net", "P1", 120);
        assert_eq!(store.chats_list("s1").unwrap().len(), 2, "two chats before the mapping");

        store.lid_pn_put("s1", "64000000000001", "5511990000001", 1).unwrap();
        let rekeyed = store.consolidate_lid_chats("s1").unwrap();
        assert_eq!(rekeyed, 2, "both @lid messages re-keyed to the PN chat");

        let chats = store.chats_list("s1").unwrap();
        assert_eq!(chats.len(), 1, "merged into a single chat");
        assert_eq!(chats[0].jid, "5511990000001@s.whatsapp.net");
        // Idempotent — nothing left to re-key.
        assert_eq!(store.consolidate_lid_chats("s1").unwrap(), 0);
    }

    #[test]
    fn lid_pn_map_round_trips_both_directions() {
        let store = Store::open(":memory:").unwrap();
        seed_session(&store, "s1");

        assert!(store.lid_to_pn("s1", "64000000000001").unwrap().is_none());
        assert!(store.pn_to_lid("s1", "5511990000001").unwrap().is_none());

        store
            .lid_pn_put("s1", "64000000000001", "5511990000001", 10)
            .unwrap();
        assert_eq!(
            store.lid_to_pn("s1", "64000000000001").unwrap().as_deref(),
            Some("5511990000001")
        );
        assert_eq!(
            store.pn_to_lid("s1", "5511990000001").unwrap().as_deref(),
            Some("64000000000001")
        );

        // Upsert: same LID, new PN replaces.
        store
            .lid_pn_put("s1", "64000000000001", "5511000000000", 20)
            .unwrap();
        assert_eq!(
            store.lid_to_pn("s1", "64000000000001").unwrap().as_deref(),
            Some("5511000000000")
        );
        // Scoped per session.
        assert!(store.lid_to_pn("s2", "64000000000001").unwrap().is_none());
    }

    #[test]
    fn message_secret_round_trips_first_writer_wins_and_prunes() {
        let store = Store::open(":memory:").unwrap();
        seed_session(&store, "s1");

        assert!(store.message_secret_get("s1", "MID1").unwrap().is_none());

        let secret = vec![0xABu8; 32];
        store
            .message_secret_put("s1", "MID1", "chat@s.whatsapp.net", "555@s.whatsapp.net", &secret, 100)
            .unwrap();
        let (sender, got) = store.message_secret_get("s1", "MID1").unwrap().unwrap();
        assert_eq!(sender, "555@s.whatsapp.net");
        assert_eq!(got, secret);

        // First-writer-wins: a re-arrival with a different secret does not clobber.
        store
            .message_secret_put("s1", "MID1", "chat@s.whatsapp.net", "555@s.whatsapp.net", &[0u8; 32], 200)
            .unwrap();
        assert_eq!(store.message_secret_get("s1", "MID1").unwrap().unwrap().1, secret);

        // Scoped per session.
        assert!(store.message_secret_get("s2", "MID1").unwrap().is_none());

        // Pruned on the message age clock (created_at < cutoff).
        store.prune(Some(150), None, None).unwrap();
        assert!(store.message_secret_get("s1", "MID1").unwrap().is_none());
    }

    #[test]
    fn message_mark_edited_applies_in_place_and_surfaces_flag() {
        let store = Store::open(":memory:").unwrap();
        seed_session(&store, "s1");
        let insert = |id: &str, body: &str| {
            store
                .message_insert(
                    &NewMessage {
                        session_id: "s1",
                        chat_jid: "c@s",
                        message_id: id,
                        sender_jid: "x@s",
                        from_me: false,
                        timestamp: 100,
                        msg_type: "text",
                        body_text: Some(body),
                        payload_json: "{}",
                        status: None,
                    },
                    true,
                )
                .unwrap();
        };
        insert("M1", "original");
        insert("M2", "keep me");

        // Unknown target → false (caller falls back to a standalone row).
        assert!(!store.message_mark_edited("s1", "NOPE", Some("x")).unwrap());

        // In-place edit replaces body + sets the flag; no new row is created.
        assert!(store.message_mark_edited("s1", "M1", Some("edited!")).unwrap());
        // None body marks edited but keeps the text.
        assert!(store.message_mark_edited("s1", "M2", None).unwrap());

        let rows = store.messages_list("s1", Some("c@s"), None, i64::MAX, 50).unwrap();
        assert_eq!(rows.len(), 2, "edit updates in place, no extra row");
        let m1 = rows.iter().find(|r| r.message_id == "M1").unwrap();
        assert_eq!(m1.body_text.as_deref(), Some("edited!"));
        assert!(m1.edited);
        let m2 = rows.iter().find(|r| r.message_id == "M2").unwrap();
        assert_eq!(m2.body_text.as_deref(), Some("keep me"));
        assert!(m2.edited);
    }

    #[test]
    fn contacts_list_collapses_lid_into_pn_once_mapped() {
        let store = Store::open(":memory:").unwrap();
        seed_session(&store, "s1");
        // Same person recorded under PN (no name) and LID (with push name).
        store
            .contact_upsert("s1", "5511990000001@s.whatsapp.net", None, None)
            .unwrap();
        store
            .contact_upsert("s1", "64000000000001@lid", None, Some("Henry"))
            .unwrap();
        // No mapping yet → two separate contacts (the reported symptom).
        assert_eq!(store.contacts_list("s1").unwrap().len(), 2);

        // Learn LID↔PN → the two collapse into one, keeping the name.
        store
            .lid_pn_put("s1", "64000000000001", "5511990000001", 1)
            .unwrap();
        let list = store.contacts_list("s1").unwrap();
        assert_eq!(list.len(), 1, "lid + pn merge into one contact");
        assert_eq!(list[0].jid, "5511990000001@s.whatsapp.net");
        assert_eq!(list[0].push_name.as_deref(), Some("Henry"));

        // An unmapped @lid contact passes through unchanged.
        store
            .contact_upsert("s1", "70000000000009@lid", None, Some("Stranger"))
            .unwrap();
        assert_eq!(store.contacts_list("s1").unwrap().len(), 2);
    }

    #[test]
    fn pns_without_lid_mapping_targets_named_and_unmapped_pns_only() {
        let store = Store::open(":memory:").unwrap();
        seed_session(&store, "s1");
        // A NAMED PN contact with no LID mapping — must be a sweep target (the
        // whole point of broadening past the old unnamed-chats-only query; a
        // named contact still duplicates until its LID is resolved).
        store
            .contact_upsert("s1", "5511990000001@s.whatsapp.net", Some("Maria"), None)
            .unwrap();
        // A PN contact that already has a mapping — excluded.
        store
            .contact_upsert("s1", "5511990000002@s.whatsapp.net", None, None)
            .unwrap();
        store
            .lid_pn_put("s1", "64000000000002", "5511990000002", 1)
            .unwrap();
        // An @lid contact is not a PN target (usync resolves BY phone number).
        store
            .contact_upsert("s1", "64000000000003@lid", None, Some("X"))
            .unwrap();

        let targets = store.pns_without_lid_mapping("s1", 100).unwrap();
        assert!(
            targets.contains(&"5511990000001@s.whatsapp.net".to_string()),
            "named-but-unmapped PN contact must be a target"
        );
        assert!(
            !targets.iter().any(|j| j.contains("5511990000002")),
            "already-mapped PN must be excluded"
        );
        assert!(
            !targets.iter().any(|j| j.ends_with("@lid")),
            "@lid contacts are not PN sweep targets"
        );
    }

    #[test]
    fn sender_key_round_trips_and_is_scoped() {
        let store = Store::open(":memory:").unwrap();
        seed_session(&store, "s1");
        let group = "120363000000000000@g.us";
        let sender = "64000000000001.1:19@lid";

        assert!(store.sender_key_load("s1", group, sender).unwrap().is_none());
        store.sender_key_save("s1", group, sender, b"record-v1").unwrap();
        assert_eq!(
            store.sender_key_load("s1", group, sender).unwrap().as_deref(),
            Some(&b"record-v1"[..])
        );
        // Upsert replaces the record (chain advances on each message).
        store.sender_key_save("s1", group, sender, b"record-v2").unwrap();
        assert_eq!(
            store.sender_key_load("s1", group, sender).unwrap().as_deref(),
            Some(&b"record-v2"[..])
        );
        // Scoped per (session, group, sender).
        assert!(store.sender_key_load("s1", group, "other@lid").unwrap().is_none());
        assert!(store.sender_key_load("s1", "other@g.us", sender).unwrap().is_none());
    }

    #[test]
    fn egress_targets_round_trip() {
        let store = Store::open(":memory:").unwrap();
        seed_session(&store, "s1");

        // Empty to start.
        assert!(store.egress_get("s1", "webhook").unwrap().is_none());
        assert!(store.egress_list_for_session("s1").unwrap().is_empty());

        // Insert a webhook target.
        let wh = EgressTarget {
            session_id: "s1".into(),
            kind: "webhook".into(),
            enabled: true,
            events: Some("message,message_sent".into()),
            secret: Some("shh".into()),
            config: r#"{"url":"https://example.test/hook"}"#.into(),
            updated_at: 10,
        };
        store.egress_set(&wh).unwrap();
        assert_eq!(store.egress_get("s1", "webhook").unwrap().as_ref(), Some(&wh));

        // Upsert (same PK) overwrites, doesn't duplicate.
        let wh2 = EgressTarget { enabled: false, updated_at: 20, ..wh.clone() };
        store.egress_set(&wh2).unwrap();
        let got = store.egress_get("s1", "webhook").unwrap().unwrap();
        assert!(!got.enabled);
        assert_eq!(got.updated_at, 20);
        assert_eq!(store.egress_list_for_session("s1").unwrap().len(), 1);

        // A second kind coexists (PK is session_id + kind).
        let rmq = EgressTarget {
            session_id: "s1".into(),
            kind: "rabbitmq".into(),
            enabled: true,
            events: None,
            secret: None,
            config: r#"{"uri":"amqp://localhost","exchange":"wa","routing_key":"ev"}"#.into(),
            updated_at: 30,
        };
        store.egress_set(&rmq).unwrap();
        assert_eq!(store.egress_list_for_session("s1").unwrap().len(), 2);
        assert_eq!(store.egress_list_all().unwrap().len(), 2);

        // Delete one, the other survives.
        store.egress_delete("s1", "webhook").unwrap();
        assert!(store.egress_get("s1", "webhook").unwrap().is_none());
        assert_eq!(store.egress_list_for_session("s1").unwrap(), vec![rmq]);

        // FK cascade: deleting the session drops its targets.
        store.session_delete("s1").unwrap();
        assert!(store.egress_list_all().unwrap().is_empty());
    }

    /// Live Postgres backend round-trip. Gated on `RUWA_PG_TEST_URL` + `RUWA_LIVE_TEST=1`
    /// (e.g. `postgres://henrysilva:admin@localhost:5433/postgres`). Exercises the
    /// same domain methods the app uses, plus the cross-instance lease state
    /// machine against two PgStore "instances" sharing the DB.
    #[test]
    #[ignore]
    fn pg_backend_round_trips() {
        if std::env::var("RUWA_LIVE_TEST").as_deref() != Ok("1") {
            return;
        }
        let url = std::env::var("RUWA_PG_TEST_URL").expect("set RUWA_PG_TEST_URL");
        let store = Store::open(&url).unwrap();
        let sid = format!("pgtest-{}", crate::session::uuid_v4());

        // create_session writes the session row + a prekey batch (secrets sealed).
        let pk_priv = [9u8; 32];
        let pk_pub = [8u8; 32];
        store
            .create_session(
                &NewSession {
                    id: &sid,
                    label: Some("pg"),
                    status: "pending",
                    jid: None,
                    registration_id: 1234,
                    noise_priv: &[1u8; 32],
                    noise_pub: &[2u8; 32],
                    identity_priv: &[3u8; 32],
                    identity_pub: &[4u8; 32],
                    spk_id: 7,
                    spk_priv: &[5u8; 32],
                    spk_pub: &[6u8; 32],
                    spk_sig: &[0u8; 64],
                    adv_secret: &[7u8; 32],
                    api_key: "k",
                    created_at: 100,
                    updated_at: 100,
                },
                &[(1, &pk_priv, &pk_pub)],
            )
            .unwrap();

        // device keys round-trip (incl. unseal of the 4 secret columns).
        let dk = store.device_keys_load(&sid).unwrap().unwrap();
        assert_eq!(dk.registration_id, 1234);
        assert_eq!(dk.noise_priv, vec![1u8; 32]);
        assert_eq!(dk.adv_secret, vec![7u8; 32]);
        // prekey private round-trips (sealed → unsealed).
        assert_eq!(store.prekey_load_private(&sid, 1).unwrap().unwrap(), pk_priv.to_vec());
        assert_eq!(store.prekey_count_uploaded(&sid).unwrap(), 0);

        // signal session round-trip.
        store.signal_session_save(&sid, "peer.1", b"record-bytes", 200).unwrap();
        assert_eq!(store.signal_session_load(&sid, "peer.1").unwrap().unwrap(), b"record-bytes".to_vec());

        // messages + list.
        store
            .message_insert(
                &NewMessage {
                    session_id: &sid,
                    chat_jid: "c@s",
                    message_id: "m1",
                    sender_jid: "x@s",
                    from_me: false,
                    timestamp: 300,
                    msg_type: "text",
                    body_text: Some("hi"),
                    payload_json: "{}",
                    status: None,
                },
                true,
            )
            .unwrap();
        let msgs = store.messages_list(&sid, Some("c@s"), None, i64::MAX, 10).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].body_text.as_deref(), Some("hi"));

        // lease state machine across two PgStore "instances" on the same DB.
        let a = Store::open(&url).unwrap();
        let b = Store::open(&url).unwrap();
        let now = 1000i64;
        assert!(a.lease_acquire(&sid, "A", 60, now).unwrap());
        assert!(!b.lease_acquire(&sid, "B", 60, now).unwrap()); // A holds fresh
        // Stale steal: B acquires once A's lease is past TTL.
        assert!(b.lease_acquire(&sid, "B", 60, now + 1000).unwrap());
        assert!(!a.lease_renew(&sid, "A", now + 1000).unwrap()); // A lost it

        // cleanup (FK cascade drops prekeys/messages/leases/signal rows).
        store.session_delete(&sid).unwrap();
        assert!(store.device_keys_load(&sid).unwrap().is_none());
    }

    /// Regression: the Postgres backend must work when driven from inside a tokio
    /// runtime (the app's `#[tokio::main]`). The sync `postgres` crate's internal
    /// `Runtime::block_on` panics "cannot start a runtime from within a runtime"
    /// on a tokio worker thread; `pg_offload` runs each call on a clean OS thread.
    /// This `#[tokio::test]` reproduces the original boot crash and proves the fix.
    /// Gated on `RUWA_PG_TEST_URL` + `RUWA_LIVE_TEST=1`.
    #[tokio::test]
    #[ignore]
    async fn pg_works_under_tokio_runtime() {
        if std::env::var("RUWA_LIVE_TEST").as_deref() != Ok("1") {
            return;
        }
        let url = std::env::var("RUWA_PG_TEST_URL").expect("set RUWA_PG_TEST_URL");
        // Open (runs migrations via batch_execute) + a write/read round-trip, all
        // under the tokio runtime. Pre-fix, `Store::open` itself panicked here;
        // post-fix, the store's `Drop` at end of scope must also stay clean.
        let store = Store::open(&url).unwrap();
        let sid = format!("pgtok-{}", crate::session::uuid_v4());
        store
            .create_session(
                &NewSession {
                    id: &sid,
                    label: Some("pgtok"),
                    status: "pending",
                    jid: None,
                    registration_id: 1,
                    noise_priv: &[1u8; 32],
                    noise_pub: &[2u8; 32],
                    identity_priv: &[3u8; 32],
                    identity_pub: &[4u8; 32],
                    spk_id: 1,
                    spk_priv: &[5u8; 32],
                    spk_pub: &[6u8; 32],
                    spk_sig: &[0u8; 64],
                    adv_secret: &[7u8; 32],
                    api_key: "k",
                    created_at: 1,
                    updated_at: 1,
                },
                &[(1, &[9u8; 32], &[8u8; 32])],
            )
            .unwrap();
        store.signal_session_save(&sid, "peer.1", b"rec", 1).unwrap();
        assert_eq!(store.signal_session_load(&sid, "peer.1").unwrap().unwrap(), b"rec".to_vec());
        store.session_delete(&sid).unwrap();
    }

    #[test]
    fn in_memory_store_shares_schema_across_calls() {
        // Pool of one shared connection: a write via one checkout is visible to
        // the next. (Regression against the per-connection :memory: pitfall.)
        let store = Store::open(":memory:").unwrap();
        store
            .with_conn(|c| {
                c.execute("CREATE TABLE t (v INTEGER)", [])?;
                c.execute("INSERT INTO t VALUES (42)", [])
            })
            .unwrap();
        let v: i64 = store
            .with_conn(|c| c.query_row("SELECT v FROM t", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(v, 42);
    }

    #[test]
    fn file_backed_pool_handles_concurrent_access() {
        // A file-backed store gets a real multi-connection pool. Hammer it from
        // several threads to prove the pool doesn't deadlock and the busy_timeout
        // lets writers on sibling connections wait rather than erroring.
        let path = std::env::temp_dir().join(format!("ruwa_pool_{}.db", crate::session::uuid_v4()));
        let store = Arc::new(Store::open(&path).unwrap());
        store
            .with_conn(|c| c.execute("CREATE TABLE k (id INTEGER PRIMARY KEY, n INTEGER)", []))
            .unwrap();

        let mut handles = Vec::new();
        for id in 0..8 {
            let s = store.clone();
            handles.push(std::thread::spawn(move || {
                for j in 0..20 {
                    s.with_conn(|c| {
                        c.execute(
                            "INSERT OR REPLACE INTO k (id, n) VALUES (?, ?)",
                            rusqlite::params![id, j],
                        )
                    })
                    .unwrap();
                    let _: i64 = s
                        .with_conn(|c| c.query_row("SELECT COUNT(*) FROM k", [], |r| r.get(0)))
                        .unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let rows: i64 = store
            .with_conn(|c| c.query_row("SELECT COUNT(*) FROM k", [], |r| r.get(0)))
            .unwrap();
        assert_eq!(rows, 8); // 8 distinct ids, last write wins
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn messages_mark_self_from_me_flips_only_own_sender() {
        let store = Store::open(":memory:").unwrap();
        seed_session(&store, "s1");
        let own_pn = "5511990000001";
        store.lid_pn_put("s1", "64000000000001", own_pn, 1).unwrap();

        let insert = |chat: &str, mid: &str, sender: &str, from_me: bool| {
            store
                .message_insert(
                    &NewMessage {
                        session_id: "s1",
                        chat_jid: chat,
                        message_id: mid,
                        sender_jid: sender,
                        from_me,
                        timestamp: 1,
                        msg_type: "text",
                        body_text: Some("hi"),
                        payload_json: "{}",
                        status: None,
                    },
                    true,
                )
                .unwrap();
        };
        let from_me_of = |mid: &str| -> bool {
            store
                .with_conn(|c| {
                    c.query_row(
                        "SELECT from_me FROM messages WHERE message_id = ?",
                        [mid],
                        |r| r.get::<_, i64>(0),
                    )
                })
                .unwrap()
                != 0
        };

        // Own group message stored (wrongly) as incoming, canonical PN sender.
        insert("g@g.us", "m_own_pn", "5511990000001@s.whatsapp.net", false);
        // Own message whose sender stayed in bare LID form.
        insert("g@g.us", "m_own_lid", "64000000000001@lid", false);
        // A real incoming message from someone else.
        insert("g@g.us", "m_other", "5511000000000@s.whatsapp.net", false);
        // An own message already correct — must stay 1.
        insert("bob@s.whatsapp.net", "m_already", "5511990000001@s.whatsapp.net", true);

        let fixed = store
            .messages_mark_self_from_me("s1", own_pn, Some("64000000000001"))
            .unwrap();
        assert_eq!(fixed, 2); // the two own from_me=0 rows

        assert!(from_me_of("m_own_pn"));
        assert!(from_me_of("m_own_lid"));
        assert!(!from_me_of("m_other")); // someone else untouched
        assert!(from_me_of("m_already"));

        // Idempotent: a second pass changes nothing.
        assert_eq!(
            store.messages_mark_self_from_me("s1", own_pn, Some("64000000000001")).unwrap(),
            0
        );
    }

    #[test]
    fn metrics_samples_insert_history_names_and_prune() {
        let store = Store::open(":memory:").unwrap();
        // Two series, a few seconds apart.
        let inserted = store
            .metrics_sample_insert_batch(&[
                ("ruwa_messages_in_total", 1_000, 5.0),
                ("ruwa_messages_in_total", 1_060, 9.0),
                ("ruwa_sessions_connected", 1_000, 1.0),
            ])
            .unwrap();
        assert_eq!(inserted, 3);
        // Duplicate (name, ts) is ignored, not an error.
        let dup = store
            .metrics_sample_insert_batch(&[("ruwa_messages_in_total", 1_000, 7.0)])
            .unwrap();
        assert_eq!(dup, 0);

        // History is oldest-first and windowed by `since_ts`.
        let hist = store
            .metrics_history("ruwa_messages_in_total", 0, 100)
            .unwrap();
        assert_eq!(
            hist,
            vec![
                MetricPoint { ts: 1_000, value: 5.0 },
                MetricPoint { ts: 1_060, value: 9.0 },
            ]
        );
        let recent = store
            .metrics_history("ruwa_messages_in_total", 1_030, 100)
            .unwrap();
        assert_eq!(recent, vec![MetricPoint { ts: 1_060, value: 9.0 }]);

        // Names are the distinct sorted series.
        assert_eq!(
            store.metrics_names().unwrap(),
            vec![
                "ruwa_messages_in_total".to_string(),
                "ruwa_sessions_connected".to_string(),
            ]
        );

        // Prune drops everything strictly older than the cutoff.
        let removed = store.metrics_prune(1_060).unwrap();
        assert_eq!(removed, 2); // the two ts=1_000 rows
        assert_eq!(
            store
                .metrics_history("ruwa_messages_in_total", 0, 100)
                .unwrap(),
            vec![MetricPoint { ts: 1_060, value: 9.0 }]
        );
    }

    #[test]
    fn log_ring_insert_query_filter_and_prune() {
        let store = Store::open(":memory:").unwrap();
        let n = store
            .log_ring_insert_batch(&[
                (1_000, 2, "INFO", "ruwa::session", "connected"),
                (2_000, 3, "WARN", "ruwa::session", "lease lost"),
                (3_000, 4, "ERROR", "ruwa::store", "db write failed"),
            ])
            .unwrap();
        assert_eq!(n, 3);

        // All levels, newest-first.
        let all = store.log_ring_query(0, i64::MAX, 100).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].message, "db write failed");
        assert_eq!(all[2].message, "connected");

        // Min-severity filter: warn+ drops the info line.
        let warn_plus = store.log_ring_query(3, i64::MAX, 100).unwrap();
        assert_eq!(warn_plus.len(), 2);
        assert!(warn_plus.iter().all(|r| r.level == "WARN" || r.level == "ERROR"));

        // Keyset cursor: page after the newest id.
        let newest_id = all[0].id;
        let older = store.log_ring_query(0, newest_id, 100).unwrap();
        assert_eq!(older.len(), 2);

        // Prune to newest 1 → only the ERROR row survives.
        let removed = store.log_ring_prune(1, 0).unwrap();
        assert_eq!(removed, 2);
        let kept = store.log_ring_query(0, i64::MAX, 100).unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].level, "ERROR");

        // Age prune removes the rest.
        let removed_age = store.log_ring_prune(100, i64::MAX).unwrap();
        assert_eq!(removed_age, 1);
        assert!(store.log_ring_query(0, i64::MAX, 100).unwrap().is_empty());
    }

    #[test]
    fn event_log_insert_list_and_prune() {
        let store = Store::open(":memory:").unwrap();
        seed_session(&store, "s1");

        // Append a handful of events with increasing timestamps.
        for i in 0..5 {
            store
                .event_log_insert("s1", 1_000 + i, "connected", r#"{"type":"connected"}"#)
                .unwrap();
        }
        store
            .event_log_insert("s1", 2_000, "message", r#"{"type":"message","id":"m1"}"#)
            .unwrap();

        // Newest-first, full page.
        let all = store.event_log_list("s1", i64::MAX, None, 100).unwrap();
        assert_eq!(all.len(), 6);
        assert_eq!(all[0].event_type, "message"); // highest id first
        assert_eq!(all[0].ts, 2_000);

        // Type filter.
        let msgs = store.event_log_list("s1", i64::MAX, Some("message"), 100).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].event_type, "message");

        // Keyset cursor: ask for rows older than the newest id.
        let newest_id = all[0].id;
        let older = store.event_log_list("s1", newest_id, None, 100).unwrap();
        assert_eq!(older.len(), 5);
        assert!(older.iter().all(|r| r.id < newest_id));

        // Prune to the newest 2 (age cutoff in the past keeps everything else).
        let removed = store.event_log_prune("s1", 2, 0).unwrap();
        assert_eq!(removed, 4);
        let kept = store.event_log_list("s1", i64::MAX, None, 100).unwrap();
        assert_eq!(kept.len(), 2);

        // Age-based prune: cutoff above all remaining ts wipes them.
        let removed_age = store.event_log_prune("s1", 100, i64::MAX).unwrap();
        assert_eq!(removed_age, 2);
        assert!(store.event_log_list("s1", i64::MAX, None, 100).unwrap().is_empty());
    }
}
