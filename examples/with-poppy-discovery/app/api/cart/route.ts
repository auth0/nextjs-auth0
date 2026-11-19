import { clearCart, getCart, respond } from "@/lib/carts";

// GET: this session's cart. DELETE: empty it.
export const GET = () => respond(getCart);
export const DELETE = () => respond(clearCart);
