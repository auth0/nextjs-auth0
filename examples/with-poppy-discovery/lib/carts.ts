import { NextResponse } from "next/server";

import { auth0 } from "@/lib/auth0";

// The carts API. Every route needs an Auth0 access token for its audience.
const API = process.env.CARTS_API_URL ?? "http://localhost:4000";

export type CartItem = {
  productId: string;
  name: string;
  price: number;
  quantity: number;
};

export type Cart = { id: string; items: CartItem[]; total: number };

class CartError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

// Which cart belongs to which Poppy session. The carts API lists every cart to
// every caller, so the app keeps this itself and only touches its own cart.
// Demo only: a real app would use its own storage.
const store = globalThis as typeof globalThis & {
  poppyCartIds?: Map<string, string>;
};
const cartIds = (store.poppyCartIds ??= new Map<string, string>());

// The cart is for an agent guest only, and uses the guest's access token.
async function requireGuest() {
  const poppy = await auth0.poppy.getContext();
  const guest = await auth0.getAnonymousSession();

  if (poppy.kind !== "agent" || poppy.state !== "guest" || !guest) {
    throw new CartError(403, "The cart is only available to an agent guest.");
  }
  return {
    token: guest.accessToken,
    key: `${poppy.act.sub}|${poppy.act.poppy_sid}`
  };
}

async function call(token: string, path: string, init: RequestInit = {}) {
  let response: Response;
  try {
    response = await fetch(`${API}${path}`, {
      ...init,
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json"
      },
      cache: "no-store"
    });
  } catch {
    throw new CartError(502, `Could not reach the carts API at ${API}.`);
  }

  if (response.status === 401) {
    throw new CartError(
      401,
      "The carts API did not accept the guest's access token. Check that AUTH0_AUDIENCE is the carts API's identifier."
    );
  }
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new CartError(
      response.status,
      body?.error ?? "The carts API returned an error."
    );
  }
  return response;
}

// This session's cart, created on first use.
async function currentCart(token: string, key: string): Promise<Cart> {
  const id = cartIds.get(key);
  if (id) {
    try {
      return await (await call(token, `/carts/${id}`)).json();
    } catch (error) {
      // The carts API forgot it, for example after a restart: start a new one.
      if (!(error instanceof CartError) || error.status !== 404) throw error;
    }
  }

  const created: Cart = await (
    await call(token, "/carts", { method: "POST", body: "{}" })
  ).json();
  cartIds.set(key, created.id);
  return created;
}

async function onCart(path: string, init?: RequestInit): Promise<Cart> {
  const { token, key } = await requireGuest();
  const cart = await currentCart(token, key);
  return (await call(token, `/carts/${cart.id}${path}`, init)).json();
}

export async function getCart(): Promise<Cart> {
  const { token, key } = await requireGuest();
  return currentCart(token, key);
}

export const addItem = (item: CartItem) =>
  onCart("/items", { method: "POST", body: JSON.stringify(item) });

export const setQuantity = (productId: string, quantity: number) =>
  onCart(`/items/${encodeURIComponent(productId)}`, {
    method: "PATCH",
    body: JSON.stringify({ quantity })
  });

export const removeItem = (productId: string) =>
  onCart(`/items/${encodeURIComponent(productId)}`, { method: "DELETE" });

export const clearCart = () =>
  onCart("", { method: "PUT", body: JSON.stringify({ items: [] }) });

// Runs a cart action and turns its errors into JSON responses.
export async function respond(action: () => Promise<unknown>) {
  try {
    return NextResponse.json(await action(), {
      headers: { "Cache-Control": "no-store" }
    });
  } catch (error) {
    if (error instanceof CartError) {
      return NextResponse.json(
        { error: error.message },
        { status: error.status }
      );
    }
    throw error;
  }
}
