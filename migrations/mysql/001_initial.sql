-- ZCT-SLMS 初始数据库结构
-- 此文件定义首次安装使用的基础表结构

CREATE TABLE IF NOT EXISTS admins
(
    id            BIGINT PRIMARY KEY AUTO_INCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    salt          TEXT    NOT NULL,
    display_name  TEXT,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    last_login_at INTEGER,
    status        INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_admins_username ON admins (username);


CREATE TABLE IF NOT EXISTS users
(
    id            BIGINT PRIMARY KEY AUTO_INCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    salt          TEXT    NOT NULL,
    display_name  TEXT,
    balance       INTEGER NOT NULL DEFAULT 0,
    expires_at    INTEGER NOT NULL DEFAULT -1,
    status        INTEGER NOT NULL DEFAULT 1,
    created_by    INTEGER,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);
CREATE INDEX IF NOT EXISTS idx_users_status ON users (status);


CREATE TABLE IF NOT EXISTS sub_users
(
    id            BIGINT PRIMARY KEY AUTO_INCREMENT,
    parent_id     INTEGER NOT NULL,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    salt          TEXT    NOT NULL,
    display_name  TEXT,
    quota_limit   INTEGER NOT NULL DEFAULT 0,
    quota_used    INTEGER NOT NULL DEFAULT 0,
    expires_at    INTEGER NOT NULL DEFAULT -1,
    status        INTEGER NOT NULL DEFAULT 1,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    FOREIGN KEY (parent_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sub_users_parent ON sub_users (parent_id);
CREATE INDEX IF NOT EXISTS idx_sub_users_username ON sub_users (username);


CREATE TABLE IF NOT EXISTS apps
(
    id           BIGINT PRIMARY KEY AUTO_INCREMENT,
    owner_id     INTEGER NOT NULL,
    appid        TEXT    NOT NULL UNIQUE,
    name         TEXT    NOT NULL,
    description  TEXT,

    -- App API Secret
    secret       TEXT    NOT NULL DEFAULT '',

    -- NONE / AES256-GCM / Base64 / Hex
    dec_mode     TEXT    NOT NULL DEFAULT 'NONE',

    -- Decode Secret （if supported)
    dec_key      TEXT    NOT NULL DEFAULT '',

    -- NONE / IP / DEVICE / IP_AND_DEVICE
    binding_mode TEXT    NOT NULL DEFAULT 'NONE',

    -- HMAC-SHA256 签名校验开关: 0=off, 1=on
    sign_enable  INTEGER NOT NULL DEFAULT 0,

    -- App 公告/通知
    notice       TEXT    NOT NULL DEFAULT '',

    status       INTEGER NOT NULL DEFAULT 1,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL,

    FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_apps_appid ON apps (appid);
CREATE INDEX IF NOT EXISTS idx_apps_owner_id ON apps (owner_id);


CREATE TABLE IF NOT EXISTS licenses
(
    id                    BIGINT PRIMARY KEY AUTO_INCREMENT,
    app_id                INTEGER NOT NULL,

    license               TEXT    NOT NULL,
    remark                TEXT,

    created_at            INTEGER NOT NULL,
    activated_at          INTEGER,
    expires_at            INTEGER NOT NULL DEFAULT -1,

    -- unused / active / expired / banned / deleted
    status                TEXT    NOT NULL DEFAULT 'unused',
    banned                INTEGER NOT NULL DEFAULT 0,

    -- NONE / IP / DEVICE / IP_AND_DEVICE
    binding_mode          TEXT    NOT NULL DEFAULT 'NONE',

    bound_ip_hash         TEXT,
    bound_device_hash     TEXT,

    last_used_at          INTEGER,
    last_used_ip          TEXT,
    last_used_device_hash TEXT,

    unbind_count          INTEGER NOT NULL DEFAULT 0,
    unbind_limit          INTEGER NOT NULL DEFAULT 0,

    unbind_time_cost      INTEGER NOT NULL DEFAULT 0,

    unbind_count_cost     INTEGER NOT NULL DEFAULT 0,

    max_devices           INTEGER NOT NULL DEFAULT 1,
    max_ips               INTEGER NOT NULL DEFAULT 1,

    created_by            INTEGER NOT NULL,
    -- OWNER / SUBUSER
    created_by_role       TEXT    NOT NULL DEFAULT 'OWNER',

    updated_at            INTEGER NOT NULL,

    -- 卡密类型
    license_type          TEXT    NOT NULL DEFAULT '',

    -- PLAIN / ENCRYPTED (for future use)
    storage_mode          TEXT    NOT NULL DEFAULT 'PLAIN',

    FOREIGN KEY (app_id) REFERENCES apps (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_licenses_app_id
    ON licenses (app_id);

CREATE INDEX IF NOT EXISTS idx_licenses_license
    ON licenses (license);

CREATE UNIQUE INDEX IF NOT EXISTS idx_licenses_app_license
    ON licenses (app_id, license);

CREATE INDEX IF NOT EXISTS idx_licenses_status
    ON licenses (status);

CREATE INDEX IF NOT EXISTS idx_licenses_expires_at
    ON licenses (expires_at);

CREATE INDEX IF NOT EXISTS idx_licenses_banned
    ON licenses (banned);

CREATE INDEX IF NOT EXISTS idx_licenses_created_by
    ON licenses (created_by);


CREATE TABLE IF NOT EXISTS license_bindings
(
    id          BIGINT PRIMARY KEY AUTO_INCREMENT,
    license_id  INTEGER NOT NULL,
    ip_hash     TEXT,
    device_hash TEXT,
    bound_at    INTEGER NOT NULL,

    FOREIGN KEY (license_id) REFERENCES licenses (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_bindings_license
    ON license_bindings (license_id);

CREATE INDEX IF NOT EXISTS idx_bindings_ip
    ON license_bindings (ip_hash);

CREATE INDEX IF NOT EXISTS idx_bindings_device
    ON license_bindings (device_hash);


CREATE TABLE IF NOT EXISTS license_unbind_records
(
    id                 BIGINT PRIMARY KEY AUTO_INCREMENT,
    license_id         INTEGER NOT NULL,
    reason             TEXT,

    before_expires     INTEGER NOT NULL,
    after_expires      INTEGER NOT NULL,

    cost_count         INTEGER NOT NULL DEFAULT 0,
    cost_time          INTEGER NOT NULL DEFAULT 0,

    unbind_count_after INTEGER NOT NULL,

    ip                 TEXT,
    operator_id        INTEGER,
    created_at         INTEGER NOT NULL,

    FOREIGN KEY (license_id) REFERENCES licenses (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_unbind_license
    ON license_unbind_records (license_id);


CREATE TABLE IF NOT EXISTS sessions
(
    id         BIGINT PRIMARY KEY AUTO_INCREMENT,

    -- ADMIN / USER / SUBUSER
    user_type  TEXT    NOT NULL,

    user_id    INTEGER NOT NULL,
    token_hash TEXT    NOT NULL,
    expires_at INTEGER NOT NULL,

    revoked    INTEGER NOT NULL DEFAULT 0,

    created_at INTEGER NOT NULL,
    created_ip TEXT,
    user_agent TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_token_hash
    ON sessions (token_hash);

CREATE INDEX IF NOT EXISTS idx_sessions_user
    ON sessions (user_type, user_id);

CREATE INDEX IF NOT EXISTS idx_sessions_expires
    ON sessions (expires_at);


CREATE TABLE IF NOT EXISTS temporary_tokens
(
    id          BIGINT PRIMARY KEY AUTO_INCREMENT,
    token_hash  TEXT    NOT NULL UNIQUE,
    description TEXT,

    max_uses    INTEGER NOT NULL DEFAULT 1,
    used_count  INTEGER NOT NULL DEFAULT 0,

    expires_at  INTEGER NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0,

    created_at  INTEGER NOT NULL,
    created_by  INTEGER NOT NULL,

    used_by_ip  TEXT
);

CREATE INDEX IF NOT EXISTS idx_temp_tokens_hash
    ON temporary_tokens (token_hash);


CREATE TABLE IF NOT EXISTS invites
(
    id             BIGINT PRIMARY KEY AUTO_INCREMENT,
    token_hash     TEXT    NOT NULL UNIQUE,

    inviter_id     INTEGER NOT NULL,

    -- ADMIN / OWNER
    inviter_role   TEXT    NOT NULL,

    -- OWNER / SUBUSER
    target_role    TEXT    NOT NULL,

    -- JSON: 子用户可分配的 APP id 列表
    target_apps    TEXT,

    quota_limit    INTEGER NOT NULL DEFAULT 0,
    uses_remaining INTEGER NOT NULL DEFAULT 1,

    expires_at     INTEGER,
    created_at     INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_invites_token
    ON invites (token_hash);


CREATE TABLE IF NOT EXISTS user_app_permissions
(
    id          BIGINT PRIMARY KEY AUTO_INCREMENT,
    sub_user_id INTEGER NOT NULL,
    app_id      INTEGER NOT NULL,

    created_at  INTEGER NOT NULL,

    FOREIGN KEY (sub_user_id) REFERENCES sub_users (id) ON DELETE CASCADE,
    FOREIGN KEY (app_id) REFERENCES apps (id) ON DELETE CASCADE,

    UNIQUE (sub_user_id, app_id)
);

CREATE INDEX IF NOT EXISTS idx_perm_subuser
    ON user_app_permissions (sub_user_id);

CREATE INDEX IF NOT EXISTS idx_perm_app
    ON user_app_permissions (app_id);


CREATE TABLE IF NOT EXISTS ip_whitelist
(
    id          BIGINT PRIMARY KEY AUTO_INCREMENT,
    ip          TEXT    NOT NULL,
    description TEXT,
    created_at  INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_whitelist_ip
    ON ip_whitelist (ip);


CREATE TABLE IF NOT EXISTS rate_limits
(
    id           BIGINT PRIMARY KEY AUTO_INCREMENT,

    -- IP / APPID / FUNCTIONID / LICENSE / API
    target_type  TEXT    NOT NULL,

    target_value TEXT    NOT NULL,

    -- 例如 LoginFail / LicenseVerifyFail
    action       TEXT    NOT NULL,

    fail_count   INTEGER NOT NULL DEFAULT 0,
    last_fail_at INTEGER,

    banned_until INTEGER,

    updated_at   INTEGER NOT NULL,

    UNIQUE (target_type, target_value, action)
);

CREATE INDEX IF NOT EXISTS idx_ratelimit_target
    ON rate_limits (target_type, target_value);

CREATE INDEX IF NOT EXISTS idx_ratelimit_banned
    ON rate_limits (banned_until);


CREATE TABLE IF NOT EXISTS nonces
(
    id        BIGINT PRIMARY KEY AUTO_INCREMENT,
    app_id    INTEGER NOT NULL,

    nonce     TEXT    NOT NULL,
    timestamp INTEGER NOT NULL,
    used_at   INTEGER NOT NULL,

    FOREIGN KEY (app_id) REFERENCES apps (id) ON DELETE CASCADE,

    UNIQUE (app_id, nonce)
);

CREATE INDEX IF NOT EXISTS idx_nonces_app
    ON nonces (app_id);


CREATE TABLE IF NOT EXISTS audit_logs
(
    id            BIGINT PRIMARY KEY AUTO_INCREMENT,

    -- ADMIN / OWNER / SUBUSER / ANON / CLIENT
    actor_type    TEXT    NOT NULL,

    actor_id      INTEGER,

    action        TEXT    NOT NULL,

    -- LICENSE / APP / USER / FUNCTION / ...
    target_type   TEXT    NOT NULL,

    target_id     INTEGER,

    -- JSON 详情
    target_detail TEXT,

    -- success / fail
    result        TEXT    NOT NULL DEFAULT 'success',

    ip            TEXT,
    extra         TEXT,

    created_at    INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_actor
    ON audit_logs (actor_type, actor_id);

CREATE INDEX IF NOT EXISTS idx_audit_action
    ON audit_logs (action);

CREATE INDEX IF NOT EXISTS idx_audit_created
    ON audit_logs (created_at);

CREATE INDEX IF NOT EXISTS idx_audit_target
    ON audit_logs (target_type, target_id);


CREATE TABLE IF NOT EXISTS api_logs
(
    id          BIGINT PRIMARY KEY AUTO_INCREMENT,

    method      TEXT    NOT NULL,
    path        TEXT    NOT NULL,

    status_code INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL,

    ip          TEXT,

    app_id      INTEGER,

    user_type   TEXT,
    user_id     INTEGER,

    license_id  INTEGER,

    created_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_api_logs_created
    ON api_logs (created_at);

CREATE INDEX IF NOT EXISTS idx_api_logs_ip
    ON api_logs (ip);

CREATE INDEX IF NOT EXISTS idx_api_logs_app
    ON api_logs (app_id);


CREATE TABLE IF NOT EXISTS update_channels
(
    id          BIGINT PRIMARY KEY AUTO_INCREMENT,
    app_id      INTEGER NOT NULL,

    -- stable / rc / beta / alpha / canary
    channel     TEXT    NOT NULL,

    description TEXT,
    created_at  INTEGER NOT NULL,

    FOREIGN KEY (app_id) REFERENCES apps (id) ON DELETE CASCADE,

    UNIQUE (app_id, channel)
);

CREATE INDEX IF NOT EXISTS idx_channels_app
    ON update_channels (app_id);


CREATE TABLE IF NOT EXISTS update_versions
(
    id              BIGINT PRIMARY KEY AUTO_INCREMENT,
    channel_id      INTEGER NOT NULL,

    version         TEXT    NOT NULL,
    release_time    INTEGER NOT NULL,

    download_url    TEXT    NOT NULL,

    file_hash       TEXT    NOT NULL,
    hash_algorithm  TEXT    NOT NULL DEFAULT 'SHA256',

    changelog       TEXT,
    minimum_version TEXT,

    created_at      INTEGER NOT NULL,

    FOREIGN KEY (channel_id) REFERENCES update_channels (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_versions_channel
    ON update_versions (channel_id);

CREATE INDEX IF NOT EXISTS idx_versions_version
    ON update_versions (version);


CREATE TABLE IF NOT EXISTS system_config
(
    key         TEXT PRIMARY KEY,
    value       TEXT    NOT NULL,
    description TEXT,
    updated_at  INTEGER NOT NULL
);


INSERT IGNORE INTO system_config(key, value, description, updated_at)
VALUES ('license_timer_paused',
        '0',
        '全局暂停卡密计时 (0=运行 1=暂停)',
        UNIX_TIMESTAMP());


INSERT IGNORE INTO system_config(key, value, description, updated_at)
VALUES ('license_timer_paused_at',
        '0',
        '上次暂停时刻 Unix timestamp',
        UNIX_TIMESTAMP());


INSERT IGNORE INTO system_config(key, value, description, updated_at)
VALUES ('license_timer_offset',
        '0',
        '累积暂停偏移秒数',
        UNIX_TIMESTAMP());


INSERT IGNORE INTO system_config(key, value, description, updated_at)
VALUES ('admin_security_level',
        'LAN',
        '管理接口安全等级 LOCAL/LAN/PUBLIC',
        UNIX_TIMESTAMP());


INSERT IGNORE INTO system_config(key, value, description, updated_at)
VALUES ('replay_window_seconds',
        '60',
        'Nonce 重放时间窗口（秒）',
        UNIX_TIMESTAMP());


INSERT IGNORE INTO system_config(key, value, description, updated_at)
VALUES ('api_rate_limit_ip_per_sec',
        '100',
        '单 IP API 限流 (req/s)',
        UNIX_TIMESTAMP());


INSERT IGNORE INTO system_config(key, value, description, updated_at)
VALUES ('api_rate_limit_app_per_sec',
        '500',
        '单 APP API 限流 (req/s)',
        UNIX_TIMESTAMP());


INSERT IGNORE INTO system_config(key, value, description, updated_at)
VALUES ('api_rate_limit_license_per_sec',
        '10',
        '单卡密限流 (req/s)'
           , UNIX_TIMESTAMP());
