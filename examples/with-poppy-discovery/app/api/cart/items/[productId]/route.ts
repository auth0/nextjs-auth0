import { removeItem, respond, setQuantity } from "@/lib/carts";

type Context = { params: Promise<{ productId: string }> };

// PATCH: set an item's quantity. DELETE: remove the item.
export async function PATCH(request: Request, { params }: Context) {
  const { productId } = await params;
  const { quantity } = await request.json();
  return respond(() => setQuantity(productId, quantity));
}

export async function DELETE(_request: Request, { params }: Context) {
  const { productId } = await params;
  return respond(() => removeItem(productId));
}
