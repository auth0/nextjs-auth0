export function ensureLeadingSlash(value: string) {
  return value && !value.startsWith("/") ? `/${value}` : value;
}

export function ensureTrailingSlash(value: string) {
  return value && !value.endsWith("/") ? `${value}/` : value;
}

export function ensureNoLeadingSlash(value: string) {
  return value && value.startsWith("/")
    ? value.substring(1, value.length)
    : value;
}

export const removeTrailingSlash = (path: string) =>
  path.endsWith("/") ? path.slice(0, -1) : path;

export const normalizeWithBasePath = (path: string) => {
  const basePath = process.env.NEXT_PUBLIC_BASE_PATH;

  if (!basePath) {
    return path;
  }

  // basePath can be `docs` or `/docs`
  const sanitizedBasePath = ensureLeadingSlash(basePath);

  return ensureTrailingSlash(sanitizedBasePath) + ensureNoLeadingSlash(path);
};
