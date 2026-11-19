import { addItem, respond } from "@/lib/carts";

// POST: add an item. Adding a product that's already there raises its quantity.
export async function POST(request: Request) {
  const { productId, name, price, quantity } = await request.json();
  return respond(() => addItem({ productId, name, price, quantity }));
}
