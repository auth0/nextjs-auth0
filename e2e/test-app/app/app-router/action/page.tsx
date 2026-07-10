"use client";

import { useState } from "react";
import { getSessionAction, updateSessionAction } from "./action";

export default function ActionPage() {
  const [status, setStatus] = useState("");
  const [email, setEmail] = useState("");

  return (
    <main>
      <p id="status">{status}</p>
      <p id="email">{email}</p>
      <button
        id="check-session"
        onClick={async () => {
          const res = await getSessionAction();
          setStatus(res.status);
          setEmail(res.email ?? "");
        }}
      >
        Check session
      </button>
      <button
        id="update-session"
        onClick={async () => {
          const res = await updateSessionAction();
          setStatus(res.status);
        }}
      >
        Update session
      </button>
    </main>
  );
}
