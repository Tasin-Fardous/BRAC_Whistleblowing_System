-- schema.sql
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username_hash TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL, -- 'reporter', 'admin', 'auditor'
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    -- ECC encrypted profile data (Name, ID, Contact)
    profile_data_encrypted TEXT, 
    public_key_ecc TEXT, 
    public_key_rsa TEXT
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reporter_id INTEGER,
    -- RSA encrypted report content
    report_content_encrypted TEXT NOT NULL,
    attachment_encrypted TEXT,
    status TEXT DEFAULT 'pending', -- pending, assigned, reviewed
    assigned_auditor_id INTEGER,
    auditor_feedback TEXT,
    hmac_signature TEXT NOT NULL,
    FOREIGN KEY(reporter_id) REFERENCES users(id),
    FOREIGN KEY(assigned_auditor_id) REFERENCES users(id)
);
