"use client"

import React from "react"
import { SWRConfig } from "swr"

import { User } from "../../types"

export function Auth0Provider({
  user,
  children,
}: {
  user?: User
  children: React.ReactNode
}) {
  return (
    <SWRConfig
      value={{
        fallback: {
          "/auth/profile": user,
        },
      }}
    >
      {children}
    </SWRConfig>
  )
}
