import { NextRequest, NextResponse } from "next/server";
import { dbGetAll, dbDeleteById, dbClear } from "@/lib/db/session-store";

// TEST-ONLY: inspect and manipulate the SQLite session store directly.
// GET  /api/stateful/store-debug        — list all session records
// DELETE /api/stateful/store-debug?id=  — delete a specific record by ID
// DELETE /api/stateful/store-debug      — clear all records

export async function GET() {
  return NextResponse.json({ sessions: dbGetAll() });
}

export async function DELETE(req: NextRequest) {
  const id = new URL(req.url).searchParams.get("id");
  if (id) {
    const deleted = dbDeleteById(id);
    return NextResponse.json({ deleted });
  }
  dbClear();
  return NextResponse.json({ cleared: true });
}
