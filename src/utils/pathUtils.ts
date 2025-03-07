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
