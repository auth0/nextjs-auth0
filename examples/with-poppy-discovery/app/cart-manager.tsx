"use client";

import { useCallback, useEffect, useState } from "react";

type Item = {
  productId: string;
  name: string;
  price: number;
  quantity: number;
};

type Cart = { id: string; items: Item[]; total: number };

const CATALOG: Omit<Item, "quantity">[] = [
  { productId: "rain-jacket", name: "Stormline rain jacket", price: 129 },
  { productId: "trail-socks", name: "Merino trail socks", price: 18 },
  { productId: "headlamp", name: "Ridge headlamp", price: 42 },
  { productId: "water-bottle", name: "Steel water bottle", price: 24 }
];

const money = (value: number) => `$${value.toFixed(2)}`;

export function CartManager() {
  const [cart, setCart] = useState<Cart | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Every cart action goes through our own /api/cart routes, which call the
  // carts API with the guest's access token. The browser never sees the token.
  const request = useCallback(async (path: string, init?: RequestInit) => {
    setBusy(true);
    setError(null);
    try {
      const response = await fetch(`/api/cart${path}`, {
        ...init,
        headers: { "content-type": "application/json" },
        cache: "no-store"
      });
      const body = await response.json();
      if (!response.ok) {
        throw new Error(body.error ?? "Something went wrong.");
      }
      setCart(body);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    void request("");
  }, [request]);

  const add = (product: Omit<Item, "quantity">) =>
    request("/items", {
      method: "POST",
      body: JSON.stringify({ ...product, quantity: 1 })
    });

  const setQuantity = (productId: string, quantity: number) =>
    request(`/items/${encodeURIComponent(productId)}`, {
      method: "PATCH",
      body: JSON.stringify({ quantity })
    });

  const remove = (productId: string) =>
    request(`/items/${encodeURIComponent(productId)}`, { method: "DELETE" });

  const clear = () => request("", { method: "DELETE" });

  return (
    <>
      <section className="card">
        <h2>Shop</h2>
        <div className="catalog">
          {CATALOG.map((product) => (
            <div className="product" key={product.productId}>
              <div>
                <strong>{product.name}</strong>
                <div className="muted">{money(product.price)}</div>
              </div>
              <button
                className="button button-small"
                disabled={busy}
                onClick={() => add(product)}
              >
                Add
              </button>
            </div>
          ))}
        </div>
      </section>

      <section className="card">
        <h2>Your cart</h2>

        {error && <p className="error">{error}</p>}

        {cart && cart.items.length === 0 && (
          <p className="muted">Your cart is empty. Add something from the shop.</p>
        )}

        {cart && cart.items.length > 0 && (
          <>
            <table className="cart-table">
              <tbody>
                {cart.items.map((item) => (
                  <tr key={item.productId}>
                    <td>{item.name}</td>
                    <td className="qty">
                      <button
                        className="button button-small button-secondary"
                        disabled={busy || item.quantity <= 1}
                        onClick={() =>
                          setQuantity(item.productId, item.quantity - 1)
                        }
                        aria-label={`Fewer ${item.name}`}
                      >
                        −
                      </button>
                      <span>{item.quantity}</span>
                      <button
                        className="button button-small button-secondary"
                        disabled={busy}
                        onClick={() =>
                          setQuantity(item.productId, item.quantity + 1)
                        }
                        aria-label={`More ${item.name}`}
                      >
                        +
                      </button>
                    </td>
                    <td className="amount">
                      {money(item.price * item.quantity)}
                    </td>
                    <td>
                      <button
                        className="button button-small button-secondary"
                        disabled={busy}
                        onClick={() => remove(item.productId)}
                      >
                        Remove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            <div className="cart-footer">
              <strong>Total {money(cart.total)}</strong>
              <button
                className="button button-small button-secondary"
                disabled={busy}
                onClick={clear}
              >
                Clear cart
              </button>
            </div>
          </>
        )}

        {cart && <p className="note">Stored in the carts API as {cart.id}</p>}
      </section>
    </>
  );
}
