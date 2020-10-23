import { IncomingMessage } from 'http';
import Session from './session';

const map = new WeakMap();

export interface RequestRef {
  session?: Session | null;
  sessionSaved?: boolean;
  cookies?: { [key: string]: string };
}

function instance(ctx: IncomingMessage): RequestRef {
  if (!map.has(ctx)) map.set(ctx, {});
  return map.get(ctx);
}

export default instance;
