"use client";

import React from "react";
import { SWRConfig } from "swr";

import { User } from "../../types/index.js";

export function Auth0Provider({
  user,
  children
}: {
  user?: User;
  children: React.ReactNode;
}) {
  return (
    <SWRConfig
      value={{
        fallback: {
          [process.env.NEXT_PUBLIC_PROFILE_ROUTE || "/auth/profile"]: user
        }
      }}
    >
      {children}
    </SWRConfig>
  );
}
