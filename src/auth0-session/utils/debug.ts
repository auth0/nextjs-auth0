import createDebug, { Debugger } from 'debug';

export default (name: string): Debugger => createDebug('nextjs-auth0').extend(name);
