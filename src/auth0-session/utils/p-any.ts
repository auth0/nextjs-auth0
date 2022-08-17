// Lightweight Promise.any implementation
export default async <T>(iterable: Iterable<T | PromiseLike<T>>): Promise<T> => {
  return Promise.all(
    [...iterable].map((promise) => {
      return new Promise((resolve, reject) => Promise.resolve(promise).then(reject, resolve));
    })
  ).then(
    (errors) => Promise.reject(errors),
    (value) => Promise.resolve<T>(value)
  );
};
