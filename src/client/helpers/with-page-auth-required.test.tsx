/**
 * @vitest-environment jsdom
 */

import React, { JSX } from "react";
import { usePathname } from "next/navigation.js";
import { render, screen, waitFor } from "@testing-library/react";
import * as swrModule from "swr";
import {
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  vi,
  type MockedFunction
} from "vitest";

import { User } from "../../types/index.js";
import { Auth0Provider } from "../providers/auth0-provider.js";
import { withPageAuthRequired } from "./with-page-auth-required.js";

const user: User = {
  email: "foo@example.com",
  email_verified: true,
  name: "foo",
  nickname: "foo",
  picture: "foo.jpg",
  sub: "1",
  updated_at: null
};

const withAuth0Provider = ({
  user
}: { user?: User } = {}): React.ComponentType => {
  return (props: any): React.ReactElement => (
    <Auth0Provider {...props} user={user} />
  );
};

const mockUseUserUnauthenticated = () => ({
  data: undefined,
  error: undefined,
  isLoading: false,
  isValidating: false,
  mutate: vi.fn()
});

vi.mock("swr", async (importActual) => {
  const actual = await importActual<typeof swrModule>();
  return {
    ...actual,
    default: vi.fn(() => ({
      data: undefined,
      error: undefined,
      isLoading: true,
      isValidating: false,
      mutate: vi.fn()
    }))
  };
});

vi.mock("next/navigation.js", async (importActual) => {
  const actual = await importActual<typeof import("next/navigation.js")>();

  return {
    ...actual,
    usePathname: vi.fn(() => "/")
  };
});

describe("with-page-auth-required csr", () => {
  beforeAll(() => {
    Object.defineProperty(window, "location", {
      writable: true,
      value: {
        assign: vi.fn(),
        toString: () => "https://example.com"
      }
    });
  });
  afterEach(() => {
    vi.resetAllMocks();
  });

  it("should deny access to a CSR page when not authenticated", async () => {
    vi.mocked(swrModule.default).mockImplementation(mockUseUserUnauthenticated);
    const MyPage = (): JSX.Element => <>Private</>;
    const ProtectedPage = withPageAuthRequired(MyPage);

    render(<ProtectedPage />, { wrapper: withAuth0Provider() });
    await waitFor(() =>
      expect(window.location.assign).toHaveBeenCalledTimes(1)
    );
    await waitFor(() => expect(screen.queryByText("Private")).toBeNull());
  });

  it("should add user to props of CSR page when authenticated", async () => {
    vi.mocked(swrModule.default).mockImplementation(() => ({
      data: user,
      error: undefined,
      isLoading: false,
      isValidating: false,
      mutate: vi.fn()
    }));

    const ProtectedPage = withPageAuthRequired(
      ({ user }): JSX.Element => <>{user.email}</>
    );

    render(<ProtectedPage />, {
      wrapper: withAuth0Provider({ user })
    });
    await waitFor(() => expect(window.location.assign).not.toHaveBeenCalled());
    await waitFor(() =>
      expect(screen.getByText("foo@example.com")).not.toBeNull()
    );
  });

  it("should show an empty element when redirecting", async () => {
    vi.mocked(swrModule.default).mockImplementation(mockUseUserUnauthenticated);

    const MyPage = (): JSX.Element => <>Private</>;
    const ProtectedPage = withPageAuthRequired(MyPage);

    const { container } = render(<ProtectedPage />, {
      wrapper: withAuth0Provider()
    });
    await waitFor(() => expect(container.innerHTML).toBe(""));
  });

  it("should show a custom element when redirecting", async () => {
    vi.mocked(swrModule.default).mockImplementation(mockUseUserUnauthenticated);

    const MyPage = (): JSX.Element => <>Private</>;
    const OnRedirecting = (): JSX.Element => <>Redirecting</>;
    const ProtectedPage = withPageAuthRequired(MyPage, {
      onRedirecting: OnRedirecting
    });

    render(<ProtectedPage />, { wrapper: withAuth0Provider() });
    await waitFor(() => expect(screen.getByText("Redirecting")).not.toBeNull());
  });

  it("should show an empty fallback in case of error", async () => {
    vi.mocked(swrModule.default).mockImplementation(() => ({
      data: undefined,
      error: new Error("Unauthorized"),
      isLoading: false,
      isValidating: false,
      mutate: vi.fn()
    }));

    const MyPage = (): JSX.Element => <>Private</>;
    const ProtectedPage = withPageAuthRequired(MyPage);

    const { container } = render(<ProtectedPage />, {
      wrapper: withAuth0Provider()
    });
    await waitFor(() => expect(container.innerHTML).toBe(""));
  });

  it("should show a custom fallback in case of error", async () => {
    vi.mocked(swrModule.default).mockImplementation(() => ({
      data: undefined,
      error: new Error("Unauthorized"),
      isLoading: false,
      isValidating: false,
      mutate: vi.fn()
    }));

    const MyPage = (): JSX.Element => <>Private</>;
    const OnError = (): JSX.Element => <>Error</>;
    const ProtectedPage = withPageAuthRequired(MyPage, { onError: OnError });

    render(<ProtectedPage />, { wrapper: withAuth0Provider() });
    await waitFor(() => expect(screen.getByText("Error")).not.toBeNull());
  });

  it("should use a custom login URL", async () => {
    process.env.NEXT_PUBLIC_LOGIN_ROUTE = "/api/foo";

    vi.mocked(swrModule.default).mockImplementation(mockUseUserUnauthenticated);
    const MyPage = (): JSX.Element => <>Private</>;
    const ProtectedPage = withPageAuthRequired(MyPage);

    render(<ProtectedPage />, { wrapper: withAuth0Provider() });
    await waitFor(() =>
      expect(window.location.assign).toHaveBeenCalledWith(
        expect.stringContaining("/api/foo")
      )
    );
    delete process.env.NEXT_PUBLIC_LOGIN_ROUTE;
  });

  it("should return to the root path", async () => {
    window.location.toString = vi.fn(() => "https://example.net");

    vi.mocked(swrModule.default).mockImplementation(mockUseUserUnauthenticated);
    vi.mocked(usePathname).mockReturnValue("/");
    const MyPage = (): JSX.Element => <>Private</>;
    const ProtectedPage = withPageAuthRequired(MyPage);

    render(<ProtectedPage />, { wrapper: withAuth0Provider() });
    await waitFor(() =>
      expect(window.location.assign).toHaveBeenCalledWith(
        expect.stringContaining(`?returnTo=${encodeURIComponent("/")}`)
      )
    );
  });

  it("should return to the current path", async () => {
    window.location.toString = vi.fn(() => "https://example.net/foo");

    vi.mocked(swrModule.default).mockImplementation(mockUseUserUnauthenticated);
    vi.mocked(usePathname).mockReturnValue("/foo");
    const MyPage = (): JSX.Element => <>Private</>;
    const ProtectedPage = withPageAuthRequired(MyPage);

    render(<ProtectedPage />, { wrapper: withAuth0Provider() });
    await waitFor(() =>
      expect(window.location.assign).toHaveBeenCalledWith(
        expect.stringContaining(`?returnTo=${encodeURIComponent("/foo")}`)
      )
    );
  });

  it("should accept a custom returnTo URL", async () => {
    vi.mocked(swrModule.default).mockImplementation(mockUseUserUnauthenticated);
    const MyPage = (): JSX.Element => <>Private</>;
    const ProtectedPage = withPageAuthRequired(MyPage, { returnTo: "/foo" });

    render(<ProtectedPage />, { wrapper: withAuth0Provider() });
    await waitFor(() =>
      expect(window.location.assign).toHaveBeenCalledWith(
        expect.stringContaining(`?returnTo=${encodeURIComponent("/foo")}`)
      )
    );
  });

  it("should preserve multiple query params in the returnTo URL", async () => {
    vi.mocked(swrModule.default).mockImplementation(mockUseUserUnauthenticated);
    const MyPage = (): JSX.Element => <>Private</>;
    const ProtectedPage = withPageAuthRequired(MyPage, {
      returnTo: "/foo?bar=baz&qux=quux"
    });

    render(<ProtectedPage />, { wrapper: withAuth0Provider() });
    await waitFor(() => {
      expect(window.location.assign).toHaveBeenCalled();
    });
    const url = new URL(
      (window.location.assign as MockedFunction<typeof window.location.assign>)
        .mock.calls[0][0],
      "https://example.com"
    );
    expect(url.searchParams.get("returnTo")).toEqual("/foo?bar=baz&qux=quux");
  });
});
