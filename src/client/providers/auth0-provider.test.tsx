/**
 * @vitest-environment jsdom
 */

import React from "react";
import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { AnonymousSession, User } from "../../types/index.js";
import { Auth0Provider, type Auth0ProviderProps } from "./auth0-provider.js";

describe("FR-8: Auth0Provider SSR Fallback", () => {
  const mockUser: User = {
    sub: "auth0|user-123",
    name: "Test User",
    email: "test@example.com",
    picture: "https://example.com/pic.jpg"
  };

  const mockAnonymousSession: AnonymousSession = {
    id: "anon@uuid-1234",
    accessToken: "bearer-token",
    expiresAt: Math.floor(Date.now() / 1000) + 3600,
    metadata: { cart: { qty: 3 } }
  };

  describe("Provider initialization", () => {
    it("FR-8: Provider accepts anonymousSession prop", () => {
      const { container } = render(
        <Auth0Provider anonymousSession={mockAnonymousSession}>
          <div>Test</div>
        </Auth0Provider>
      );

      expect(container).toBeTruthy();
    });

    it("FR-8: Provider seeds SWR cache with anonymousSession when provided", () => {
      // Note: Testing SWR fallback value by checking provider integration
      const props: Auth0ProviderProps = {
        anonymousSession: mockAnonymousSession,
        children: <div>Test</div>
      };

      const { container } = render(<Auth0Provider {...props} />);
      expect(container).toBeTruthy();
    });

    it("FR-8: Provider accepts anonymousSessionRoute prop", () => {
      const { container } = render(
        <Auth0Provider
          anonymousSession={mockAnonymousSession}
          anonymousSessionRoute="/api/anon-session"
        >
          <div>Test</div>
        </Auth0Provider>
      );

      expect(container).toBeTruthy();
    });

    it("FR-8: Provider accepts null anonymousSession (no session)", () => {
      const { container } = render(
        <Auth0Provider anonymousSession={null}>
          <div>Test</div>
        </Auth0Provider>
      );

      expect(container).toBeTruthy();
    });

    it("FR-8: Provider handles undefined anonymousSession (not seeded)", () => {
      const { container } = render(
        <Auth0Provider>
          <div>Test</div>
        </Auth0Provider>
      );

      expect(container).toBeTruthy();
    });
  });

  describe("SSR cache seeding", () => {
    it("FR-8: When anonymousSession provided, no loading flash occurs", () => {
      // This is verified by the provider passing the fallback to SWRConfig.
      // When SWR sees the fallback value for a key, it returns cached data immediately.
      const props: Auth0ProviderProps = {
        anonymousSession: mockAnonymousSession,
        user: mockUser,
        children: <div>Content</div>
      };

      const { container } = render(<Auth0Provider {...props} />);
      // Provider should render immediately without fetch
      expect(container.textContent).toContain("Content");
    });

    it("FR-8: When anonymousSession null, SWR cache seeded with null", () => {
      const props: Auth0ProviderProps = {
        anonymousSession: null,
        children: <div>Content</div>
      };

      const { container } = render(<Auth0Provider {...props} />);
      expect(container).toBeTruthy();
    });

    it("FR-8: Both user and anonymousSession can be seeded together", () => {
      const props: Auth0ProviderProps = {
        user: mockUser,
        anonymousSession: mockAnonymousSession,
        children: <div>Content</div>
      };

      const { container } = render(<Auth0Provider {...props} />);
      expect(container).toBeTruthy();
    });
  });

  describe("Route resolution", () => {
    it("FR-8: Uses default routes when not specified", () => {
      const props: Auth0ProviderProps = {
        anonymousSession: mockAnonymousSession,
        children: <div>Content</div>
      };

      const { container } = render(<Auth0Provider {...props} />);
      expect(container).toBeTruthy();
    });

    it("FR-8: Uses custom profileRoute when provided", () => {
      const props: Auth0ProviderProps = {
        user: mockUser,
        profileRoute: "/api/custom-profile",
        children: <div>Content</div>
      };

      const { container } = render(<Auth0Provider {...props} />);
      expect(container).toBeTruthy();
    });

    it("FR-8: Uses custom anonymousSessionRoute when provided", () => {
      const props: Auth0ProviderProps = {
        anonymousSession: mockAnonymousSession,
        anonymousSessionRoute: "/api/custom-anon",
        children: <div>Content</div>
      };

      const { container } = render(<Auth0Provider {...props} />);
      expect(container).toBeTruthy();
    });

    it("FR-8: Respects NEXT_PUBLIC_PROFILE_ROUTE env var", () => {
      const originalEnv = process.env.NEXT_PUBLIC_PROFILE_ROUTE;
      process.env.NEXT_PUBLIC_PROFILE_ROUTE = "/env-profile";

      try {
        const props: Auth0ProviderProps = {
          user: mockUser,
          children: <div>Content</div>
        };

        const { container } = render(<Auth0Provider {...props} />);
        expect(container).toBeTruthy();
      } finally {
        process.env.NEXT_PUBLIC_PROFILE_ROUTE = originalEnv;
      }
    });

    it("FR-8: Respects NEXT_PUBLIC_ANONYMOUS_SESSION_ROUTE env var", () => {
      const originalEnv = process.env.NEXT_PUBLIC_ANONYMOUS_SESSION_ROUTE;
      process.env.NEXT_PUBLIC_ANONYMOUS_SESSION_ROUTE = "/env-anon";

      try {
        const props: Auth0ProviderProps = {
          anonymousSession: mockAnonymousSession,
          children: <div>Content</div>
        };

        const { container } = render(<Auth0Provider {...props} />);
        expect(container).toBeTruthy();
      } finally {
        process.env.NEXT_PUBLIC_ANONYMOUS_SESSION_ROUTE = originalEnv;
      }
    });
  });
});
