"use client";

import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";

export default function LoginToLinkButton() {
  const searchParams = useSearchParams();
  const [linked, setLinked] = useState(false);

  useEffect(() => {
    // Detect ?linked=true query param after callback redirect
    if (searchParams.get("linked") === "true") {
      setLinked(true);
    }
  }, [searchParams]);

  const handleLogin = () => {
    // SEC-1: NO session_token param in authorizationParameters.
    // SDK injects session_token from cookie automatically (3-layer fixation protection).
    window.location.href = "/auth/login?returnTo=/demo";
  };

  return (
    <div>
      <button onClick={handleLogin}>Login to Link</button>
      {linked && (
        <div
          style={{
            marginTop: "10px",
            padding: "10px",
            background: "#d4edda",
            border: "1px solid #c3e6cb",
            borderRadius: "5px",
            color: "#155724"
          }}
        >
          ✓ Anonymous session successfully linked to your account!
        </div>
      )}
    </div>
  );
}
