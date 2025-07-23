import { Auth0Client, TransactionStore } from "@auth0/nextjs-auth0/server";

// Example 1: Single Transaction Mode (Prevents Cookie Accumulation)
const singleTransactionStore = new TransactionStore({
  secret: process.env.AUTH0_SECRET!,
  enableParallelTransactions: false,
  cookieOptions: {
    maxAge: 1800, // 30 minutes
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production"
  }
});

export const auth0Single = new Auth0Client({
  transactionStore: singleTransactionStore,
  domain: process.env.AUTH0_DOMAIN!,
  clientId: process.env.AUTH0_CLIENT_ID!,
  clientSecret: process.env.AUTH0_CLIENT_SECRET!,
  appBaseUrl: process.env.APP_BASE_URL!,
  secret: process.env.AUTH0_SECRET!,
  routes: {
    login: "/auth/login",
    logout: "/auth/logout",
    callback: "/auth/callback"
  }
});

// Example 2: Parallel Transactions with Custom Settings
const parallelTransactionStore = new TransactionStore({
  secret: process.env.AUTH0_SECRET!,
  enableParallelTransactions: true, // Default
  cookieOptions: {
    maxAge: 2700, // 45 minutes
    prefix: "__myapp_txn_", // Custom prefix
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/"
  }
});

export const auth0Parallel = new Auth0Client({
  transactionStore: parallelTransactionStore,
  domain: process.env.AUTH0_DOMAIN!,
  clientId: process.env.AUTH0_CLIENT_ID!,
  clientSecret: process.env.AUTH0_CLIENT_SECRET!,
  appBaseUrl: process.env.APP_BASE_URL!,
  secret: process.env.AUTH0_SECRET!,
  routes: {
    login: "/auth/login",
    logout: "/auth/logout",
    callback: "/auth/callback"
  }
});

// Example 3: Using Default Configuration (No Custom TransactionStore)
export const auth0Default = new Auth0Client({
  // TransactionStore will be created automatically with default settings:
  // - enableParallelTransactions: true
  // - maxAge: 3600 (1 hour)
  // - prefix: "__txn_"
  domain: process.env.AUTH0_DOMAIN!,
  clientId: process.env.AUTH0_CLIENT_ID!,
  clientSecret: process.env.AUTH0_CLIENT_SECRET!,
  appBaseUrl: process.env.APP_BASE_URL!,
  secret: process.env.AUTH0_SECRET!,
  routes: {
    login: "/auth/login",
    logout: "/auth/logout", 
    callback: "/auth/callback"
  }
});

// Use the appropriate client based on your needs
export const auth0 = auth0Single; // or auth0Parallel, auth0Default
