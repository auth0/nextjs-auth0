import { IncomingMessage, ServerResponse } from "http";
import { Socket } from "net";
import { NextApiRequest, NextApiResponse } from "next";
import { cookies } from "next/headers.js";
import { NextRequest, NextResponse } from "next/server.js";
import { afterEach, describe, expect, it, vi } from "vitest";

import { generateSecret } from "../../test/utils.js";
import { SessionData } from "../../types/index.js";
import { Auth0Client } from "../client.js";
import { encrypt, ReadonlyRequestCookies, RequestCookies } from "../cookies.js";
import {
  appRouteHandlerFactory,
  pageRouteHandlerFactory
} from "./with-api-auth-required.js";

describe("with-api-auth-required", () => {
  describe("app router", () => {
    vi.mock("next/headers.js", async (importActual) => {
      const actual = await importActual<typeof import("next/headers.js")>();

      return {
        ...actual,
        cookies: vi.fn().mockImplementation(async () => {
          return new RequestCookies(new Headers());
        })
      };
    });

    afterEach(() => {
      vi.clearAllMocks();
    });

    it("should protect an API route", async () => {
      const withApiAuthRequired = appRouteHandlerFactory(
        new Auth0Client({
          domain: constants.domain,
          clientId: constants.clientId,
          clientSecret: constants.clientSecret,
          appBaseUrl: constants.appBaseUrl,
          secret: constants.secret
        })
      );

      const request = new NextRequest(
        new URL("/custom-profile", constants.appBaseUrl),
        {
          method: "GET"
        }
      );
      const handler = withApiAuthRequired(async () =>
        NextResponse.json({ protected: true })
      );
      const response = await handler(request, {});
      expect(response.status).toBe(401);
    });

    it("allow access to an API route with a valid session", async () => {
      const auth0Client = new Auth0Client({
        domain: constants.domain,
        clientId: constants.clientId,
        clientSecret: constants.clientSecret,
        appBaseUrl: constants.appBaseUrl,
        secret: constants.secret
      });
      const withApiAuthRequired = appRouteHandlerFactory(auth0Client);

      vi.mocked(cookies).mockImplementation(async () => {
        const session: SessionData = {
          user: { sub: "user_123" },
          tokenSet: {
            idToken: "idt_123",
            accessToken: "at_123",
            refreshToken: "rt_123",
            expiresAt: 123456
          },
          internal: {
            sid: "auth0-sid",
            createdAt: Math.floor(Date.now() / 1000)
          }
        };
        const maxAge = 60 * 60; // 1 hour
        const expiration = Math.floor(Date.now() / 1000 + maxAge);
        const sessionCookie = await encrypt(
          session,
          constants.secret,
          expiration
        );
        const headers = new Headers();
        headers.append("cookie", `__session=${sessionCookie}`);

        return new RequestCookies(headers) as unknown as ReadonlyRequestCookies;
      });

      const request = new NextRequest(
        new URL("/custom-profile", constants.appBaseUrl),
        {
          method: "GET"
        }
      );
      const handler = withApiAuthRequired(async () =>
        NextResponse.json({ foo: "bar" })
      );
      const response = await handler(request, {});
      expect(response.status).toBe(200);
      await expect(response.json()).resolves.toEqual({ foo: "bar" });
    });

    it("allow access to an API route that updates the cookies", async () => {
      const auth0Client = new Auth0Client({
        domain: constants.domain,
        clientId: constants.clientId,
        clientSecret: constants.clientSecret,
        appBaseUrl: constants.appBaseUrl,
        secret: constants.secret
      });
      const withApiAuthRequired = appRouteHandlerFactory(auth0Client);

      vi.mocked(cookies).mockImplementation(async () => {
        const session: SessionData = {
          user: { sub: "user_123" },
          tokenSet: {
            idToken: "idt_123",
            accessToken: "at_123",
            refreshToken: "rt_123",
            expiresAt: 123456
          },
          internal: {
            sid: "auth0-sid",
            createdAt: Math.floor(Date.now() / 1000)
          }
        };
        const maxAge = 60 * 60; // 1 hour
        const expiration = Math.floor(Date.now() / 1000 + maxAge);
        const sessionCookie = await encrypt(
          session,
          constants.secret,
          expiration
        );
        const headers = new Headers();
        headers.append("cookie", `__session=${sessionCookie}`);

        return new RequestCookies(headers) as unknown as ReadonlyRequestCookies;
      });

      const request = new NextRequest(
        new URL("/custom-profile", constants.appBaseUrl),
        {
          method: "GET"
        }
      );
      const handler = withApiAuthRequired(async () => {
        const res = NextResponse.json({ foo: "bar" });
        res.cookies.set("foo", "bar");
        res.headers.set("baz", "bar");
        return res;
      });
      const response = (await handler(request, {})) as NextResponse;
      expect(response.status).toBe(200);
      await expect(response.json()).resolves.toEqual({ foo: "bar" });
      expect(response.cookies.get("foo")?.value).toBe("bar");
      expect(response.headers.get("baz")).toBe("bar");
    });
  });

  describe("pages router", () => {
    it("should protect an API route", async () => {
      const withApiAuthRequired = pageRouteHandlerFactory(
        new Auth0Client({
          domain: constants.domain,
          clientId: constants.clientId,
          clientSecret: constants.clientSecret,
          appBaseUrl: constants.appBaseUrl,
          secret: constants.secret
        })
      );

      const request = Object.assign(
        new IncomingMessage(new Socket()),
        {}
      ) as NextApiRequest;
      const response = new ServerResponse(
        request
      ) as unknown as NextApiResponse;
      response.status = vi.fn().mockReturnValue(response);
      response.json = vi.fn();
      const handler = withApiAuthRequired(async () =>
        NextResponse.json({ protected: true })
      );
      await handler(request, response);
      expect(response.status).toHaveBeenCalledWith(401);
    });

    it("allow access to an API route with a valid session", async () => {
      const withApiAuthRequired = pageRouteHandlerFactory(
        new Auth0Client({
          domain: constants.domain,
          clientId: constants.clientId,
          clientSecret: constants.clientSecret,
          appBaseUrl: constants.appBaseUrl,
          secret: constants.secret
        })
      );

      const session: SessionData = {
        user: { sub: "user_123" },
        tokenSet: {
          idToken: "idt_123",
          accessToken: "at_123",
          refreshToken: "rt_123",
          expiresAt: 123456
        },
        internal: {
          sid: "auth0-sid",
          createdAt: Math.floor(Date.now() / 1000)
        }
      };
      const maxAge = 60 * 60; // 1 hour
      const expiration = Math.floor(Date.now() / 1000 + maxAge);
      const sessionCookie = await encrypt(
        session,
        constants.secret,
        expiration
      );

      const request = Object.assign(new IncomingMessage(new Socket()), {
        cookies: {
          __session: sessionCookie
        },
        headers: {
          cookie: `__session=${sessionCookie}`
        }
      }) as unknown as NextApiRequest;
      const response = new ServerResponse(
        request
      ) as unknown as NextApiResponse;
      response.status = vi.fn().mockReturnValue(response);
      response.json = vi.fn();

      const handler = withApiAuthRequired(async (_, res) =>
        res.status(200).json({ foo: "bar" })
      );
      await handler(request, response);

      expect(response.status).toHaveBeenCalledWith(200);
      expect(response.json).toHaveBeenCalledWith({ foo: "bar" });
    });
  });
});

const constants = {
  domain: "example.us.auth0.com",
  clientId: "client_123",
  clientSecret: "client-secret",
  appBaseUrl: "https://example.com",
  sub: "user_123",
  secret: await generateSecret(32)
};
