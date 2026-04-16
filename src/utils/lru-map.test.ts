import { describe, expect, it } from "vitest";

import { LruMap } from "./lru-map.js";

describe("LruMap", () => {
  describe("constructor", () => {
    it("should accept positive maxSize", () => {
      const map = new LruMap(10);
      expect(map.size).toBe(0);
    });

    it("should throw for maxSize = 0", () => {
      expect(() => new LruMap(0)).toThrow("maxSize must be greater than 0");
    });

    it("should throw for negative maxSize", () => {
      expect(() => new LruMap(-5)).toThrow("maxSize must be greater than 0");
    });
  });

  describe("get", () => {
    it("should return value for existing key", () => {
      const map = new LruMap(10);
      map.set("key", "value");
      expect(map.get("key")).toBe("value");
    });

    it("should return undefined for missing key", () => {
      const map = new LruMap(10);
      expect(map.get("key")).toBeUndefined();
    });

    it("should promote accessed key to most-recent", () => {
      const map = new LruMap(3);
      map.set("a", 1);
      map.set("b", 2);
      map.set("c", 3);

      // Access "a" to promote it
      map.get("a");

      // Insert "d", which should evict "b" (not "a" since it was promoted)
      map.set("d", 4);

      expect(map.has("a")).toBe(true);
      expect(map.has("b")).toBe(false);
      expect(map.has("c")).toBe(true);
      expect(map.has("d")).toBe(true);
    });

    it("should handle undefined values correctly (promotion check using has)", () => {
      const map = new LruMap(3);
      map.set("a", undefined as any);
      map.set("b", undefined as any);
      map.set("c", undefined as any);

      // Get "a" to promote it (should work even though value is undefined)
      const result = map.get("a");
      expect(result).toBeUndefined();

      // Insert "d", which should evict "b" (not "a" since it was promoted)
      map.set("d", 1);

      expect(map.has("a")).toBe(true);
      expect(map.has("b")).toBe(false);
      expect(map.has("c")).toBe(true);
      expect(map.has("d")).toBe(true);
    });
  });

  describe("set", () => {
    it("should store new entry", () => {
      const map = new LruMap(10);
      map.set("key", "value");
      expect(map.get("key")).toBe("value");
      expect(map.size).toBe(1);
    });

    it("should update existing entry without increasing size", () => {
      const map = new LruMap(10);
      map.set("key", "value1");
      expect(map.size).toBe(1);
      map.set("key", "value2");
      expect(map.size).toBe(1);
      expect(map.get("key")).toBe("value2");
    });

    it("should promote existing entry on update (move to end)", () => {
      const map = new LruMap(3);
      map.set("a", 1);
      map.set("b", 2);
      map.set("c", 3);

      // Update "a" to promote it
      map.set("a", 10);

      // Insert "d", which should evict "b" (not "a" since it was updated)
      map.set("d", 4);

      expect(map.has("a")).toBe(true);
      expect(map.has("b")).toBe(false);
      expect(map.has("c")).toBe(true);
      expect(map.has("d")).toBe(true);
    });

    it("should evict oldest entry when at capacity", () => {
      const map = new LruMap(2);
      map.set("a", 1);
      map.set("b", 2);
      map.set("c", 3);

      // "a" should be evicted
      expect(map.size).toBe(2);
      expect(map.has("a")).toBe(false);
      expect(map.has("b")).toBe(true);
      expect(map.has("c")).toBe(true);
    });

    it("should verify eviction order: insert A,B,C with maxSize=2 evicts A", () => {
      const map = new LruMap(2);
      map.set("A", "valueA");
      map.set("B", "valueB");
      expect(map.size).toBe(2);

      map.set("C", "valueC");
      expect(map.size).toBe(2);

      // Verify A was evicted (oldest)
      expect(map.has("A")).toBe(false);
      expect(map.has("B")).toBe(true);
      expect(map.has("C")).toBe(true);

      // Verify values are correct
      expect(map.get("B")).toBe("valueB");
      expect(map.get("C")).toBe("valueC");
    });
  });

  describe("has", () => {
    it("should return true for existing key without promoting", () => {
      const map = new LruMap(3);
      map.set("a", 1);
      map.set("b", 2);
      map.set("c", 3);

      // Check existence without promoting
      expect(map.has("a")).toBe(true);

      // Insert "d" and verify "a" is evicted (it was NOT promoted by has)
      map.set("d", 4);

      expect(map.has("a")).toBe(false);
      expect(map.has("b")).toBe(true);
      expect(map.has("c")).toBe(true);
      expect(map.has("d")).toBe(true);
    });

    it("should return false for missing key", () => {
      const map = new LruMap(10);
      expect(map.has("key")).toBe(false);
    });
  });

  describe("delete", () => {
    it("should remove entry and return true", () => {
      const map = new LruMap(10);
      map.set("key", "value");
      const result = map.delete("key");
      expect(result).toBe(true);
      expect(map.has("key")).toBe(false);
      expect(map.size).toBe(0);
    });

    it("should return false for missing key", () => {
      const map = new LruMap(10);
      const result = map.delete("key");
      expect(result).toBe(false);
    });

    it("should decrease size when deleting", () => {
      const map = new LruMap(10);
      map.set("a", 1);
      map.set("b", 2);
      expect(map.size).toBe(2);
      map.delete("a");
      expect(map.size).toBe(1);
    });
  });

  describe("size", () => {
    it("should return 0 for empty map", () => {
      const map = new LruMap(10);
      expect(map.size).toBe(0);
    });

    it("should return correct count after operations", () => {
      const map = new LruMap(10);
      map.set("a", 1);
      expect(map.size).toBe(1);
      map.set("b", 2);
      expect(map.size).toBe(2);
      map.delete("a");
      expect(map.size).toBe(1);
    });
  });

  describe("edge cases", () => {
    it("should handle maxSize=1 (single-entry cache)", () => {
      const map = new LruMap(1);
      map.set("a", 1);
      expect(map.size).toBe(1);
      expect(map.has("a")).toBe(true);

      map.set("b", 2);
      expect(map.size).toBe(1);
      expect(map.has("a")).toBe(false);
      expect(map.has("b")).toBe(true);

      map.set("c", 3);
      expect(map.size).toBe(1);
      expect(map.has("b")).toBe(false);
      expect(map.has("c")).toBe(true);
    });

    it("should handle promotion saves from eviction with maxSize=1", () => {
      const map = new LruMap(1);
      map.set("a", 1);
      expect(map.has("a")).toBe(true);

      // Get "a" to promote it (no-op for single entry but should work)
      map.get("a");
      expect(map.has("a")).toBe(true);

      // Set new value, should evict "a"
      map.set("b", 2);
      expect(map.has("a")).toBe(false);
      expect(map.has("b")).toBe(true);
    });

    it("should handle empty get after eviction", () => {
      const map = new LruMap(2);
      map.set("a", 1);
      map.set("b", 2);
      map.set("c", 3);

      expect(map.get("a")).toBeUndefined();
      expect(map.get("b")).toBe(2);
      expect(map.get("c")).toBe(3);
    });

    it("should handle complex LRU sequence: insert, get (promote), insert evicts non-promoted", () => {
      const map = new LruMap(2);

      // Insert A, B
      map.set("A", "valueA");
      map.set("B", "valueB");
      expect(map.size).toBe(2);

      // Promote A via get
      const a = map.get("A");
      expect(a).toBe("valueA");

      // Insert C — B should be evicted (it's oldest, A was promoted)
      map.set("C", "valueC");
      expect(map.size).toBe(2);
      expect(map.has("A")).toBe(true);
      expect(map.has("B")).toBe(false);
      expect(map.has("C")).toBe(true);

      // Promote C via get
      const c = map.get("C");
      expect(c).toBe("valueC");

      // Insert D — A should be evicted (C was just promoted)
      map.set("D", "valueD");
      expect(map.size).toBe(2);
      expect(map.has("A")).toBe(false);
      expect(map.has("C")).toBe(true);
      expect(map.has("D")).toBe(true);
    });
  });
});
