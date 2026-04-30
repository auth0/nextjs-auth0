/**
 * A generic Least-Recently-Used (LRU) Map with bounded size and automatic eviction.
 *
 * Insertion order is tracked via Map: on access via get() or set(), the item is
 * promoted to most-recent. When size exceeds maxSize, the least-recently-used
 * (oldest) entry is evicted.
 *
 * @template K - Key type
 * @template V - Value type
 * @internal
 */
export class LruMap<K, V> {
  private map = new Map<K, V>();

  constructor(private readonly maxSize: number) {
    if (maxSize <= 0) {
      throw new Error("maxSize must be greater than 0");
    }
  }

  get(key: K): V | undefined {
    if (this.map.has(key)) {
      const value = this.map.get(key)!;
      this.map.delete(key);
      this.map.set(key, value);
      return value;
    }
    return undefined;
  }

  set(key: K, value: V): void {
    if (this.map.has(key)) {
      this.map.delete(key);
    }
    if (this.map.size >= this.maxSize) {
      const oldestKey = this.map.keys().next().value;
      if (oldestKey !== undefined) {
        this.map.delete(oldestKey);
      }
    }
    this.map.set(key, value);
  }

  has(key: K): boolean {
    return this.map.has(key);
  }

  get size(): number {
    return this.map.size;
  }

  delete(key: K): boolean {
    return this.map.delete(key);
  }
}
