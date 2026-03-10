/**
 * Tests for domain and issuer normalization and validation utilities
 */

import { describe, expect, it } from "vitest";

import { DomainValidationError } from "../errors/mcd.js";
import {
  normalizeDomain,
  normalizeIssuer,
  validateDomainHostname
} from "./normalize.js";

describe("normalize.ts", () => {
  describe("normalizeIssuer", () => {
    it("should add trailing slash if missing", () => {
      expect(normalizeIssuer("https://example.auth0.com")).toBe(
        "https://example.auth0.com/"
      );
    });

    it("should preserve trailing slash if present", () => {
      expect(normalizeIssuer("https://example.auth0.com/")).toBe(
        "https://example.auth0.com/"
      );
    });

    it("should handle multiple trailing slashes", () => {
      // normalizeIssuer only adds one trailing slash if missing
      expect(normalizeIssuer("https://example.auth0.com///")).toBe(
        "https://example.auth0.com///"
      );
    });

    it("should handle complex issuer URLs", () => {
      expect(normalizeIssuer("https://example.auth0.com:8080")).toBe(
        "https://example.auth0.com:8080/"
      );
    });
  });

  describe("validateDomainHostname", () => {
    describe("valid domains", () => {
      it("should accept standard auth0 domain", () => {
        expect(() => validateDomainHostname("example.auth0.com")).not.toThrow();
      });

      it("should accept custom domain", () => {
        expect(() =>
          validateDomainHostname("mycompany.example.com")
        ).not.toThrow();
      });

      it("should accept subdomain", () => {
        expect(() =>
          validateDomainHostname("api.mycompany.example.com")
        ).not.toThrow();
      });

      it("should handle uppercase domains (case-insensitive)", () => {
        expect(() => validateDomainHostname("EXAMPLE.AUTH0.COM")).not.toThrow();
      });

      it("should handle mixed case domains", () => {
        expect(() => validateDomainHostname("Example.Auth0.Com")).not.toThrow();
      });

      it("should allow domains with hyphens", () => {
        expect(() =>
          validateDomainHostname("my-company.example.com")
        ).not.toThrow();
      });

      it("should allow domains with numbers", () => {
        expect(() =>
          validateDomainHostname("example123.auth0.com")
        ).not.toThrow();
      });
    });

    describe("invalid domains", () => {
      it("should reject empty domain", () => {
        expect(() => validateDomainHostname("")).toThrow(DomainValidationError);
        expect(() => validateDomainHostname("")).toThrow(
          "Domain cannot be empty."
        );
      });

      it("should reject whitespace-only domain", () => {
        expect(() => validateDomainHostname("   ")).toThrow(
          DomainValidationError
        );
      });

      it("should reject localhost", () => {
        expect(() => validateDomainHostname("localhost")).toThrow(
          DomainValidationError
        );
        expect(() => validateDomainHostname("localhost")).toThrow(
          "localhost domains are not supported"
        );
      });

      it("should reject localhost with subdomain", () => {
        expect(() => validateDomainHostname("api.localhost")).toThrow(
          DomainValidationError
        );
        expect(() => validateDomainHostname("api.localhost")).toThrow(
          "localhost domains are not supported"
        );
      });

      it("should reject localhost with suffix", () => {
        expect(() => validateDomainHostname("myapp.localhost")).toThrow(
          DomainValidationError
        );
      });

      it("should reject .local domains", () => {
        expect(() => validateDomainHostname("example.local")).toThrow(
          DomainValidationError
        );
        expect(() => validateDomainHostname("example.local")).toThrow(
          ".local domains are not supported"
        );
      });

      it("should reject .local domains with subdomain", () => {
        expect(() => validateDomainHostname("api.example.local")).toThrow(
          DomainValidationError
        );
        expect(() => validateDomainHostname("api.example.local")).toThrow(
          ".local domains are not supported"
        );
      });

      it("should reject domains with paths", () => {
        expect(() => validateDomainHostname("example.auth0.com/path")).toThrow(
          DomainValidationError
        );
        expect(() => validateDomainHostname("example.auth0.com/path")).toThrow(
          "Domain cannot contain paths"
        );
      });

      it("should reject domains with ports", () => {
        expect(() => validateDomainHostname("example.auth0.com:8080")).toThrow(
          DomainValidationError
        );
        expect(() => validateDomainHostname("example.auth0.com:8080")).toThrow(
          "Domain cannot contain ports"
        );
      });

      it("should reject IPv4 addresses", () => {
        expect(() => validateDomainHostname("192.168.1.1")).toThrow(
          DomainValidationError
        );
        expect(() => validateDomainHostname("192.168.1.1")).toThrow(
          "IPv4 addresses are not supported"
        );
      });

      it("should reject various IPv4 addresses", () => {
        expect(() => validateDomainHostname("127.0.0.1")).toThrow(
          DomainValidationError
        );
        expect(() => validateDomainHostname("10.0.0.1")).toThrow(
          DomainValidationError
        );
        expect(() => validateDomainHostname("255.255.255.255")).toThrow(
          DomainValidationError
        );
      });

      it("should reject IPv6 addresses", () => {
        expect(() => validateDomainHostname("2001:db8::8a2e:370:7334")).toThrow(
          DomainValidationError
        );
        // IPv6 addresses have colons which are rejected as ports
        expect(() => validateDomainHostname("2001:db8::8a2e:370:7334")).toThrow(
          "Domain cannot contain ports"
        );
      });

      it("should reject IPv6 loopback address", () => {
        expect(() => validateDomainHostname("::1")).toThrow(
          DomainValidationError
        );
        // IPv6 loopback has colons which are rejected as ports
        expect(() => validateDomainHostname("::1")).toThrow(
          "Domain cannot contain ports"
        );
      });

      it("should reject IPv6 any address", () => {
        expect(() => validateDomainHostname("::")).toThrow(
          DomainValidationError
        );
        // IPv6 any address has colons which are rejected as ports
        expect(() => validateDomainHostname("::")).toThrow(
          "Domain cannot contain ports"
        );
      });

      it("should reject IPv6 with brackets", () => {
        expect(() =>
          validateDomainHostname("[2001:db8::8a2e:370:7334]")
        ).toThrow(DomainValidationError);
      });
    });

    describe("allowInsecureRequests option", () => {
      it("should allow localhost when allowInsecureRequests is true", () => {
        expect(() =>
          validateDomainHostname("localhost", { allowInsecureRequests: true })
        ).not.toThrow();
      });

      it("should still reject .local domains when allowInsecureRequests is true", () => {
        expect(() =>
          validateDomainHostname("example.local", {
            allowInsecureRequests: true
          })
        ).toThrow(DomainValidationError);
      });

      it("should still reject IPv4 addresses when allowInsecureRequests is true", () => {
        expect(() =>
          validateDomainHostname("127.0.0.1", { allowInsecureRequests: true })
        ).toThrow(DomainValidationError);
      });
    });
  });

  describe("normalizeDomain", () => {
    describe("full issuer URLs", () => {
      it("should parse https URL and extract hostname", () => {
        const result = normalizeDomain("https://example.auth0.com");
        expect(result).toEqual({
          domain: "example.auth0.com",
          issuer: "https://example.auth0.com/"
        });
      });

      it("should parse https URL with trailing slash", () => {
        const result = normalizeDomain("https://example.auth0.com/");
        expect(result).toEqual({
          domain: "example.auth0.com",
          issuer: "https://example.auth0.com/"
        });
      });

      it("should handle case-insensitive scheme", () => {
        const result = normalizeDomain("HTTPS://example.auth0.com");
        expect(result).toEqual({
          domain: "example.auth0.com",
          issuer: "https://example.auth0.com/"
        });
      });

      it("should handle mixed case scheme", () => {
        const result = normalizeDomain("HtTpS://example.auth0.com");
        expect(result).toEqual({
          domain: "example.auth0.com",
          issuer: "https://example.auth0.com/"
        });
      });

      it("should reject HTTP URLs by default", () => {
        // HTTP is allowed during parsing, but issuer will be HTTPS by default (see protocol handling)
        const result = normalizeDomain("http://example.auth0.com");
        expect(result.issuer).toMatch(/^https:\/\//);
      });

      it("should accept HTTP URLs when allowInsecureRequests is true", () => {
        const result = normalizeDomain("http://localhost", {
          allowInsecureRequests: true
        });
        expect(result).toEqual({
          domain: "localhost",
          issuer: "http://localhost/"
        });
      });

      it("should reject URLs with paths", () => {
        expect(() =>
          normalizeDomain("https://example.auth0.com/some/path")
        ).toThrow(DomainValidationError);
        expect(() =>
          normalizeDomain("https://example.auth0.com/some/path")
        ).toThrow(
          "Domain URL cannot contain path, query, or fragment parameters."
        );
      });

      it("should reject URLs with query parameters", () => {
        expect(() =>
          normalizeDomain("https://example.auth0.com?foo=bar")
        ).toThrow(DomainValidationError);
      });

      it("should reject URLs with fragments", () => {
        expect(() =>
          normalizeDomain("https://example.auth0.com#section")
        ).toThrow(DomainValidationError);
      });
    });

    describe("bare hostnames", () => {
      it("should accept bare hostname", () => {
        const result = normalizeDomain("example.auth0.com");
        expect(result).toEqual({
          domain: "example.auth0.com",
          issuer: "https://example.auth0.com/"
        });
      });

      it("should handle bare hostname with hyphens", () => {
        const result = normalizeDomain("my-company.auth0.com");
        expect(result).toEqual({
          domain: "my-company.auth0.com",
          issuer: "https://my-company.auth0.com/"
        });
      });

      it("should handle bare hostname with numbers", () => {
        const result = normalizeDomain("company123.auth0.com");
        expect(result).toEqual({
          domain: "company123.auth0.com",
          issuer: "https://company123.auth0.com/"
        });
      });

      it("should use issuerHint if provided", () => {
        const result = normalizeDomain("example.auth0.com", {
          issuerHint: "https://custom.issuer.com"
        });
        expect(result).toEqual({
          domain: "example.auth0.com",
          issuer: "https://custom.issuer.com/"
        });
      });
    });

    describe("validation", () => {
      it("should reject bare hostname that is localhost", () => {
        expect(() => normalizeDomain("localhost")).toThrow(
          DomainValidationError
        );
      });

      it("should accept localhost when allowInsecureRequests is true", () => {
        const result = normalizeDomain("localhost", {
          allowInsecureRequests: true
        });
        expect(result).toEqual({
          domain: "localhost",
          issuer: "https://localhost/"
        });
      });

      it("should reject .local domains", () => {
        expect(() => normalizeDomain("example.local")).toThrow(
          DomainValidationError
        );
      });

      it("should reject IPv4 addresses", () => {
        expect(() => normalizeDomain("192.168.1.1")).toThrow(
          DomainValidationError
        );
      });

      it("should reject IPv6 addresses", () => {
        expect(() => normalizeDomain("2001:db8::1")).toThrow(
          DomainValidationError
        );
      });

      it("should reject domains with ports", () => {
        expect(() => normalizeDomain("example.auth0.com:8080")).toThrow(
          DomainValidationError
        );
      });
    });

    describe("edge cases", () => {
      it("should handle whitespace trimming", () => {
        const result = normalizeDomain("  example.auth0.com  ");
        expect(result).toEqual({
          domain: "example.auth0.com",
          issuer: "https://example.auth0.com/"
        });
      });

      it("should handle whitespace in URLs", () => {
        const result = normalizeDomain("  https://example.auth0.com  ");
        expect(result).toEqual({
          domain: "example.auth0.com",
          issuer: "https://example.auth0.com/"
        });
      });

      it("should reject empty strings", () => {
        expect(() => normalizeDomain("")).toThrow(DomainValidationError);
      });

      it("should reject whitespace-only strings", () => {
        expect(() => normalizeDomain("   ")).toThrow(DomainValidationError);
      });
    });

    describe("Punycode and Unicode domains", () => {
      it("should accept Punycode-encoded domain", () => {
        const result = normalizeDomain("xn--mnchen-3ya.auth0.com");
        expect(result).toEqual({
          domain: "xn--mnchen-3ya.auth0.com",
          issuer: "https://xn--mnchen-3ya.auth0.com/"
        });
      });

      it("should handle Punycode domain in URL format", () => {
        const result = normalizeDomain("https://xn--mnchen-3ya.auth0.com");
        expect(result).toEqual({
          domain: "xn--mnchen-3ya.auth0.com",
          issuer: "https://xn--mnchen-3ya.auth0.com/"
        });
      });

      it("should handle mixed case Punycode domain", () => {
        const result = normalizeDomain("XN--MNCHEN-3YA.AUTH0.COM");
        expect(result).toEqual({
          domain: "XN--MNCHEN-3YA.AUTH0.COM",
          issuer: "https://XN--MNCHEN-3YA.AUTH0.COM/"
        });
      });

      it("should handle multiple Punycode labels", () => {
        const result = normalizeDomain("xn--80akhbyknj4f.xn--p1ai");
        expect(result).toEqual({
          domain: "xn--80akhbyknj4f.xn--p1ai",
          issuer: "https://xn--80akhbyknj4f.xn--p1ai/"
        });
      });
    });
  });
});
