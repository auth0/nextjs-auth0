import type { Routes } from "../server/auth-client.js";

export function getDefaultRoutes(): Routes {
  return {
    login: process.env.NEXT_PUBLIC_LOGIN_ROUTE || "/auth/login",
    logout: "/auth/logout",
    callback: "/auth/callback",
    backChannelLogout: "/auth/backchannel-logout",
    profile: process.env.NEXT_PUBLIC_PROFILE_ROUTE || "/auth/profile",
    accessToken:
      process.env.NEXT_PUBLIC_ACCESS_TOKEN_ROUTE || "/auth/access-token",
    connectAccount: "/auth/connect"
  };
}
