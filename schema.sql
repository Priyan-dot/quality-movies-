CREATE TABLE IF NOT EXISTS videos (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  type TEXT NOT NULL CHECK (type IN ('Movie', 'Series')),
  year TEXT DEFAULT '',
  description TEXT DEFAULT '',
  poster TEXT DEFAULT '',
  drive TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
