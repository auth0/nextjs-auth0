import { NextRequest, NextResponse } from "next/server.js";

import { Auth0Client } from "../client.js";
import { toNextRequest } from "../http/next-compat.js";
import type {
  WithApiAuthRequiredAppRoute,
  WithApiAuthRequiredPageRoute
} from "./types.js";

export type {
  AppRouteHandlerFn,
  AppRouteHandlerFnContext,
  WithApiAuthRequired,
  WithApiAuthRequiredAppRoute,
  WithApiAuthRequiredPageRoute
} from "./types.js";

export const appRouteHandlerFactory =
  (client: Auth0Client): WithApiAuthRequiredAppRoute =>
  (apiRoute) =>
  async (req: NextRequest | Request, params): Promise<NextResponse> => {
    const nextReq = req instanceof Request ? toNextRequest(req) : req;

    const session = await client.getSession();

    if (!session || !session.user) {
      return NextResponse.json(
        {
          error: "not_authenticated",
          description:
            "The user does not have an active session or is not authenticated"
        },
        { status: 401 }
      );
    }

    const apiRes: NextResponse | Response = await apiRoute(nextReq, params);
    const nextApiRes: NextResponse =
      apiRes instanceof NextResponse
        ? apiRes
        : new NextResponse(apiRes.body, apiRes);

    return nextApiRes;
  };

export const pageRouteHandlerFactory =
  (client: Auth0Client): WithApiAuthRequiredPageRoute =>
  (apiRoute) =>
  async (req, res) => {
    const session = await client.getSession(req);

    if (!session || !session.user) {
      // If the user is not authenticated, return
      res.status(401).json({
        error: "not_authenticated",
        description:
          "The user does not have an active session or is not authenticated"
      });
      return;
    }

    await apiRoute(req, res);
  };
