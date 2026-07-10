import { useState } from "react";
import { getAccessToken, useUser } from "@auth0/nextjs-auth0";

export default function ClientPage() {
  const { user, isLoading, error } = useUser();
  const [tokenResult, setTokenResult] = useState("");
  const [tokenFull, setTokenFull] = useState("");

  if (isLoading) return <p id="status">loading</p>;

  if (!user) {
    return (
      <main>
        <h1 id="status">unauthenticated</h1>
        <a href="/auth/login?returnTo=/pages-router/client">Log in</a>
      </main>
    );
  }

  return (
    <main>
      <h1 id="status">authenticated</h1>
      <p id="email">{user.email}</p>
      <p id="sub">{user.sub}</p>
      <button
        id="get-token"
        onClick={async () => {
          const token = await getAccessToken();
          setTokenResult(token);
        }}
      >
        Get token
      </button>
      <input id="token-result" value={tokenResult} readOnly onChange={() => {}} />
      <button
        id="get-token-full"
        onClick={async () => {
          const res = await getAccessToken({ includeFullResponse: true });
          setTokenFull(JSON.stringify(res));
        }}
      >
        Get token full
      </button>
      <input id="token-full" value={tokenFull} readOnly onChange={() => {}} />
    </main>
  );
}
