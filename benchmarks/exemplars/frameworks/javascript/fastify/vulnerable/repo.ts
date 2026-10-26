import { Database } from 'sqlite3';

const db = new Database('app.db');

export function findNotes(owner: string, cb: (rows: any[]) => void) {
  db.all("SELECT * FROM notes WHERE owner = '" + owner + "'", (err, rows) => cb(rows));  // frame-expect: CWE-89
}
