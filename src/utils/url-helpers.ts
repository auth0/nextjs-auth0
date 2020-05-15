export default function isRelative(url: string): boolean {
  if (typeof url !== 'string') {
    throw new TypeError(`Invalid url: ${url}`);
  }
  return !/^[a-zA-Z][a-zA-Z\d+\-.]*:/.test(url);
}
