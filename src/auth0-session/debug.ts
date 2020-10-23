import createDebug from 'debug';

export default (name: string) => createDebug('nextjs-auth0').extend(name);
