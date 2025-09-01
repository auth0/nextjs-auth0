import "dotenv/config";

export const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN ?? "your-tenant.auth0.com";
export const AUTH0_AUDIENCE =
  process.env.AUTH0_AUDIENCE ?? "http://localhost:3001";
