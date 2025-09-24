import { IncomingMessage, ServerResponse } from "http";
import { Socket } from "net";
import React from "react";
import { redirect } from "next/navigation.js";
import ReactDOMServer from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";

import { generateSecret } from "../../test/utils.js";
import { Auth0Client } from "../client.js";
import { RequestCookies } from "../cookies.js";
import {
  appRouteHandlerFactory,
  pageRouteHandlerFactory
} from "./with-page-auth-required.js";

describe("with-page-auth-required ssr", () => {
  describe("app router", () => {
    vi.mock("next/navigation.js", async (importActual) => {
      const actual = await importActual<typeof import("next/navigation.js")>();

      return {
        ...actual,
        redirect: vi.fn(actual.redirect)
      };
    });

    vi.mock("next/headers.js", async (importActual) => {
      const actual = await importActual<typeof import("next/headers.js")>();

      return {
        ...actual,
        cookies: vi.fn().mockImplementation(() => {
          return new RequestCookies(new Headers());
        })
      };
    });

    afterEach(() => {
      vi.clearAllMocks();
    });

    it("should protect a page", async () => {
      const withPageAuthRequired = appRouteHandlerFactory(
        new Auth0Client({
          domain: constants.domain,
          clientId: constants.clientId,
          clientSecret: constants.clientSecret,
          appBaseUrl: constants.appBaseUrl,
          secret: constants.secret
        }),
        {
          loginUrl: "/auth/login"
        }
      );
      const handler = withPageAuthRequired(() =>
        Promise.resolve(React.createElement("div", {}, "foo"))
      );
      await expect(handler({})).rejects.toThrowError("NEXT_REDIRECT");
      expect(redirect).toHaveBeenCalledTimes(1);
      expect(redirect).toHaveBeenCalledWith("/auth/login");
    });

    it("should protect a page and redirect to returnTo option", async () => {
      const withPageAuthRequired = appRouteHandlerFactory(
        new Auth0Client({
          domain: constants.domain,
          clientId: constants.clientId,
          clientSecret: constants.clientSecret,
          appBaseUrl: constants.appBaseUrl,
          secret: constants.secret
        }),
        {
          loginUrl: "/auth/login"
        }
      );
      const handler = withPageAuthRequired(
        () => Promise.resolve(React.createElement("div", {}, "foo")),
        {
          returnTo: "/foo"
        }
      );
      await expect(handler({})).rejects.toThrowError("NEXT_REDIRECT");
      expect(redirect).toHaveBeenCalledTimes(1);
      expect(redirect).toHaveBeenCalledWith("/auth/login?returnTo=/foo");
    });

    it("should protect a page and redirect to returnTo fn option", async () => {
      const withPageAuthRequired = appRouteHandlerFactory(
        new Auth0Client({
          domain: constants.domain,
          clientId: constants.clientId,
          clientSecret: constants.clientSecret,
          appBaseUrl: constants.appBaseUrl,
          secret: constants.secret
        }),
        {
          loginUrl: "/auth/login"
        }
      );
      const handler = withPageAuthRequired(
        () => Promise.resolve(React.createElement("div", {}, "foo")),
        {
          async returnTo({ params, searchParams }: any) {
            const query = new URLSearchParams(await searchParams).toString();
            return `/foo/${(await params).slug}${query ? `?${query}` : ""}`;
          }
        }
      );
      await expect(
        handler({
          params: Promise.resolve({ slug: "bar" }),
          searchParams: Promise.resolve({ foo: "bar" })
        })
      ).rejects.toThrowError("NEXT_REDIRECT");
      expect(redirect).toHaveBeenCalledTimes(1);
      expect(redirect).toHaveBeenCalledWith(
        "/auth/login?returnTo=/foo/bar?foo=bar"
      );
    });

    it("should allow access to a page with a valid session", async () => {
      const auth0Client = new Auth0Client({
        domain: constants.domain,
        clientId: constants.clientId,
        clientSecret: constants.clientSecret,
        appBaseUrl: constants.appBaseUrl,
        secret: constants.secret
      });
      auth0Client.getSession = vi.fn().mockResolvedValue({
        user: {
          sub: constants.sub,
          name: "Test User"
        }
      });
      const withPageAuthRequired = appRouteHandlerFactory(auth0Client, {
        loginUrl: "/auth/login"
      });
      const handler = withPageAuthRequired(() =>
        Promise.resolve(React.createElement("div", {}, "foo"))
      );
      const res = await handler({});
      expect(ReactDOMServer.renderToString(res as React.ReactElement)).toBe(
        "<div>foo</div>"
      );
      expect(auth0Client.getSession).toHaveBeenCalledTimes(1);
    });

    it("should use a custom login url", async () => {
      const withPageAuthRequired = appRouteHandlerFactory(
        new Auth0Client({
          domain: constants.domain,
          clientId: constants.clientId,
          clientSecret: constants.clientSecret,
          appBaseUrl: constants.appBaseUrl,
          secret: constants.secret
        }),
        {
          loginUrl: "/api/auth/custom-login"
        }
      );
      const handler = withPageAuthRequired(() =>
        Promise.resolve(React.createElement("div", {}, "foo"))
      );
      await expect(handler({})).rejects.toThrowError("NEXT_REDIRECT");
      expect(redirect).toHaveBeenCalledTimes(1);
      expect(redirect).toHaveBeenCalledWith("/api/auth/custom-login");
    });
  });

  describe("pages router", () => {
    it("should protect a page", async () => {
      const auth0Client = new Auth0Client({
        domain: constants.domain,
        clientId: constants.clientId,
        clientSecret: constants.clientSecret,
        appBaseUrl: constants.appBaseUrl,
        secret: constants.secret
      });
      const withPageAuthRequired = pageRouteHandlerFactory(auth0Client, {
        loginUrl: "/auth/login"
      });
      const handler = withPageAuthRequired();
      const res = await handler(mockCtx());
      expect(res).toEqual({
        redirect: {
          destination: `/auth/login?returnTo=${encodeURIComponent("/protected")}`,
          permanent: false
        }
      });
    });

    it("should allow access to a page with a valid session", async () => {
      const auth0Client = new Auth0Client({
        domain: constants.domain,
        clientId: constants.clientId,
        clientSecret: constants.clientSecret,
        appBaseUrl: constants.appBaseUrl,
        secret: constants.secret
      });
      auth0Client.getSession = vi.fn().mockResolvedValue({
        user: {
          sub: constants.sub,
          name: "Test User"
        }
      });
      const withPageAuthRequired = pageRouteHandlerFactory(auth0Client, {
        loginUrl: "/auth/login"
      });
      const handler = withPageAuthRequired();
      const res = await handler(mockCtx());
      expect(res).toEqual({
        props: {
          user: {
            sub: constants.sub,
            name: "Test User"
          }
        }
      });
    });

    it("should accept a custom returnTo url", async () => {
      const auth0Client = new Auth0Client({
        domain: constants.domain,
        clientId: constants.clientId,
        clientSecret: constants.clientSecret,
        appBaseUrl: constants.appBaseUrl,
        secret: constants.secret
      });
      const withPageAuthRequired = pageRouteHandlerFactory(auth0Client, {
        loginUrl: "/auth/login"
      });
      const handler = withPageAuthRequired({
        returnTo: "/foo"
      });
      const res = await handler(mockCtx());
      expect(res).toEqual({
        redirect: {
          destination: `/auth/login?returnTo=${encodeURIComponent("/foo")}`,
          permanent: false
        }
      });
    });

    it("should accept custom server-side props", async () => {
      const auth0Client = new Auth0Client({
        domain: constants.domain,
        clientId: constants.clientId,
        clientSecret: constants.clientSecret,
        appBaseUrl: constants.appBaseUrl,
        secret: constants.secret
      });
      auth0Client.getSession = vi.fn().mockResolvedValue({
        user: {
          sub: constants.sub,
          name: "Test User"
        }
      });
      const withPageAuthRequired = pageRouteHandlerFactory(auth0Client, {
        loginUrl: "/auth/login"
      });
      const getServerSidePropsSpy = vi.fn().mockResolvedValue({
        props: {
          customProp: "value"
        }
      });
      const handler = withPageAuthRequired({
        getServerSideProps: getServerSidePropsSpy
      });
      const res = await handler(mockCtx());
      expect(res).toEqual({
        props: {
          customProp: "value",
          user: {
            sub: constants.sub,
            name: "Test User"
          }
        }
      });
      expect(getServerSidePropsSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          req: expect.any(IncomingMessage),
          res: expect.any(ServerResponse),
          query: {},
          resolvedUrl: "/protected"
        })
      );
    });

    it("should allow to override the user prop", async () => {
      const auth0Client = new Auth0Client({
        domain: constants.domain,
        clientId: constants.clientId,
        clientSecret: constants.clientSecret,
        appBaseUrl: constants.appBaseUrl,
        secret: constants.secret
      });
      auth0Client.getSession = vi.fn().mockResolvedValue({
        user: {
          sub: constants.sub,
          name: "Test User"
        }
      });
      const withPageAuthRequired = pageRouteHandlerFactory(auth0Client, {
        loginUrl: "/auth/login"
      });
      const handler = withPageAuthRequired({
        getServerSideProps: async () => ({
          props: { user: { sub: "foo" } }
        })
      });
      const res = await handler(mockCtx());
      expect(res).toEqual({
        props: {
          user: { sub: "foo" }
        }
      });
    });

    it("should allow to override the user prop with async props", async () => {
      const auth0Client = new Auth0Client({
        domain: constants.domain,
        clientId: constants.clientId,
        clientSecret: constants.clientSecret,
        appBaseUrl: constants.appBaseUrl,
        secret: constants.secret
      });
      auth0Client.getSession = vi.fn().mockResolvedValue({
        user: {
          sub: constants.sub,
          name: "Test User"
        }
      });
      const withPageAuthRequired = pageRouteHandlerFactory(auth0Client, {
        loginUrl: "/auth/login"
      });
      const handler = withPageAuthRequired({
        getServerSideProps: async () => {
          return { props: Promise.resolve({ user: { sub: "foo" } }) };
        }
      });
      const res = await handler(mockCtx());
      expect(res).toEqual({
        props: {
          user: { sub: "foo" }
        }
      });
    });

    it("should use a custom login url", async () => {
      const auth0Client = new Auth0Client({
        domain: constants.domain,
        clientId: constants.clientId,
        clientSecret: constants.clientSecret,
        appBaseUrl: constants.appBaseUrl,
        secret: constants.secret
      });
      const withPageAuthRequired = pageRouteHandlerFactory(auth0Client, {
        loginUrl: "/api/auth/custom-login"
      });
      const handler = withPageAuthRequired();
      const res = await handler(mockCtx());
      expect(res).toEqual({
        redirect: {
          destination: `/api/auth/custom-login?returnTo=${encodeURIComponent(
            "/protected"
          )}`,
          permanent: false
        }
      });
    });

    it("should preserve multiple query params in the returnTo URL", async () => {
      const auth0Client = new Auth0Client({
        domain: constants.domain,
        clientId: constants.clientId,
        clientSecret: constants.clientSecret,
        appBaseUrl: constants.appBaseUrl,
        secret: constants.secret
      });
      const withPageAuthRequired = pageRouteHandlerFactory(auth0Client, {
        loginUrl: "/auth/login"
      });
      const handler = withPageAuthRequired({
        returnTo: "/foo?bar=baz&qux=quux"
      });
      const res = await handler(mockCtx());
      expect(res).toEqual({
        redirect: {
          destination: `/auth/login?returnTo=${encodeURIComponent(
            "/foo?bar=baz&qux=quux"
          )}`,
          permanent: false
        }
      });
    });

    it("should allow access to a page with a valid session and async props", async () => {
      const auth0Client = new Auth0Client({
        domain: constants.domain,
        clientId: constants.clientId,
        clientSecret: constants.clientSecret,
        appBaseUrl: constants.appBaseUrl,
        secret: constants.secret
      });
      auth0Client.getSession = vi.fn().mockResolvedValue({
        user: {
          sub: constants.sub,
          name: "Test User"
        }
      });
      const withPageAuthRequired = pageRouteHandlerFactory(auth0Client, {
        loginUrl: "/auth/login"
      });
      const handler = withPageAuthRequired({
        getServerSideProps() {
          return Promise.resolve({ props: Promise.resolve({}) });
        }
      });
      const res = await handler(mockCtx());
      expect(res).toEqual({
        props: {
          user: {
            sub: constants.sub,
            name: "Test User"
          }
        }
      });
    });

    it("should save session when getServerSideProps completes async", async () => {
      const auth0Client = new Auth0Client({
        domain: constants.domain,
        clientId: constants.clientId,
        clientSecret: constants.clientSecret,
        appBaseUrl: constants.appBaseUrl,
        secret: constants.secret
      });
      auth0Client.getSession = vi.fn().mockResolvedValue({
        user: {
          sub: constants.sub,
          name: "Test User"
        }
      });
      auth0Client.updateSession = vi.fn().mockResolvedValue({});

      const withPageAuthRequired = pageRouteHandlerFactory(auth0Client, {
        loginUrl: "/auth/login"
      });
      const handler = withPageAuthRequired({
        async getServerSideProps(ctx) {
          await Promise.resolve();
          const session = await auth0Client.getSession(ctx.req);
          await auth0Client.updateSession(ctx.req, ctx.res, {
            ...session!,
            test: "Hello World!"
          });
          return { props: {} };
        }
      });

      const res = await handler(mockCtx());
      expect(res).toEqual({
        props: {
          user: {
            sub: constants.sub,
            name: "Test User"
          }
        }
      });
      expect(auth0Client.updateSession).toHaveBeenCalledWith(
        expect.any(IncomingMessage),
        expect.any(ServerResponse),
        expect.objectContaining({ test: "Hello World!" })
      );
    });
  });
});

function mockCtx() {
  const mockReq = Object.assign(new IncomingMessage(new Socket()), {
    cookies: {}
  });
  const mockRes = new ServerResponse(mockReq);

  return {
    resolvedUrl: "/protected",
    req: mockReq,
    res: mockRes,
    query: {}
  };
}

const constants = {
  domain: "guabu.us.auth0.com",
  clientId: "client_123",
  clientSecret: "client-secret",
  appBaseUrl: "https://example.com",
  sub: "user_123",
  secret: await generateSecret(32)
};
