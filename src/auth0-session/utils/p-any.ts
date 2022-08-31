const flip = (promise: Promise<any>) => new Promise((a, b) => promise.then(b, a));

// Lightweight Promise.any-like implementation
// Promise.all returns the first rejected promise or all resolved promises
// Promise.any returns the first resolved promise or all rejected promises
// If we flip all the promises of Promise.all then flip back the result, we get the behaviour of Promise.any
export default async (promises: Promise<any>[]) => flip(Promise.all(promises.map(flip)));
