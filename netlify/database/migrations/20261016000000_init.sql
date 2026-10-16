-- Skema awal Tabungan Cikande Hub (Postgres)
CREATE TABLE IF NOT EXISTS warga (
  id         text PRIMARY KEY,
  nama       text NOT NULL,
  alamat     text NOT NULL DEFAULT '',
  phone      text NOT NULL DEFAULT '',
  created_at double precision NOT NULL
);

CREATE TABLE IF NOT EXISTS tx (
  id       text PRIMARY KEY,
  warga_id text NOT NULL REFERENCES warga(id) ON DELETE CASCADE,
  ts       double precision NOT NULL,
  type     text NOT NULL CHECK (type IN ('SETOR','TARIK')),
  amount   double precision NOT NULL,
  note     text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_tx_warga ON tx (warga_id, ts);

CREATE TABLE IF NOT EXISTS pin (
  warga_id   text PRIMARY KEY REFERENCES warga(id) ON DELETE CASCADE,
  salt       text NOT NULL,
  hash       text NOT NULL,
  updated_at double precision NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
  warga_id text PRIMARY KEY REFERENCES warga(id) ON DELETE CASCADE,
  bulan    text NOT NULL,
  ts       double precision NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash text PRIMARY KEY,
  role       text NOT NULL,
  subject    text NOT NULL DEFAULT '',
  expires    double precision NOT NULL
);

CREATE TABLE IF NOT EXISTS fails (
  key   text PRIMARY KEY,
  count integer NOT NULL,
  until double precision NOT NULL
);

CREATE TABLE IF NOT EXISTS hits (
  key          text PRIMARY KEY,
  window_start double precision NOT NULL,
  count        integer NOT NULL
);
