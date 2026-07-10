import { DatabaseSync } from "node:sqlite";
import type { SessionData, SessionDataStore } from "@auth0/nextjs-auth0/types";

// Module-level singleton — one DB per test-app process.
// Tests can inspect or delete records directly via the store-debug route.
const db = new DatabaseSync(":memory:");

db.exec(`
  CREATE TABLE IF NOT EXISTS sessions (
    id    TEXT PRIMARY KEY,
    data  TEXT NOT NULL
  )
`);

export const sqliteSessionStore: SessionDataStore = {
  async get(id: string): Promise<SessionData | null> {
    const row = db.prepare("SELECT data FROM sessions WHERE id = ?").get(id) as
      | { data: string }
      | undefined;
    if (!row) return null;
    return JSON.parse(row.data) as SessionData;
  },

  async set(id: string, session: SessionData): Promise<void> {
    db.prepare(
      "INSERT INTO sessions (id, data) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET data = excluded.data"
    ).run(id, JSON.stringify(session));
  },

  async delete(id: string): Promise<void> {
    db.prepare("DELETE FROM sessions WHERE id = ?").run(id);
  },

  // Atomic check-and-update — used by StatefulSessionStore for rolling session safety.
  async update(id: string, session: SessionData): Promise<boolean> {
    const result = db
      .prepare("UPDATE sessions SET data = ? WHERE id = ?")
      .run(JSON.stringify(session), id);
    return result.changes > 0;
  },

  async deleteByLogoutToken(token: { sub?: string; sid?: string }): Promise<void> {
    if (token.sid) {
      // Match by session ID stored inside the session payload's internal.sid
      const rows = db.prepare("SELECT id, data FROM sessions").all() as {
        id: string;
        data: string;
      }[];
      for (const row of rows) {
        const session = JSON.parse(row.data) as SessionData;
        if (session.internal?.sid === token.sid) {
          db.prepare("DELETE FROM sessions WHERE id = ?").run(row.id);
          return;
        }
      }
    } else if (token.sub) {
      const rows = db.prepare("SELECT id, data FROM sessions").all() as {
        id: string;
        data: string;
      }[];
      for (const row of rows) {
        const session = JSON.parse(row.data) as SessionData;
        if (session.user?.sub === token.sub) {
          db.prepare("DELETE FROM sessions WHERE id = ?").run(row.id);
        }
      }
    }
  },
};

// Test-only helpers exposed to the store-debug route
export function dbGetAll(): { id: string; data: string }[] {
  return db.prepare("SELECT id, data FROM sessions").all() as {
    id: string;
    data: string;
  }[];
}

export function dbDeleteById(id: string): boolean {
  const result = db.prepare("DELETE FROM sessions WHERE id = ?").run(id);
  return result.changes > 0;
}

export function dbClear(): void {
  db.exec("DELETE FROM sessions");
}
