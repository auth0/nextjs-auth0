import React from 'react';
import { NextApiRequest, NextApiResponse } from 'next';
import { NextRequest, NextResponse } from 'next/server';
import { expectTypeOf } from 'expect-type';
import { handleAuth, HandlerError, AppRouteHandlerFnContext, withPageAuthRequired } from '../src';

describe('types', () => {
  test('should allow customisation of page router auth handlers', () => {
    expectTypeOf(handleAuth).toBeCallableWith({
      login(_req: NextApiRequest, _res: NextApiResponse) {}
    });
  });

  test('should allow customisation of page router error handler', () => {
    expectTypeOf(handleAuth).toBeCallableWith({
      onError(_req: NextApiRequest, _res: NextApiResponse, _err: HandlerError) {}
    });
  });

  test('should allow customisation of app router auth handlers', () => {
    expectTypeOf(handleAuth).toBeCallableWith({
      login(_req: NextRequest) {
        return new NextResponse();
      }
    });
  });

  test('should allow customisation of app router auth handlers with context', () => {
    expectTypeOf(handleAuth).toBeCallableWith({
      login(_req: NextRequest, _ctx: AppRouteHandlerFnContext) {
        return new NextResponse();
      }
    });
  });

  test('should allow customisation of app router auth handlers with context literal', () => {
    expectTypeOf(handleAuth).toBeCallableWith({
      login(_req: NextRequest, _ctx: { params: Record<string, string | string[]> }) {
        return new NextResponse();
      }
    });
  });

  test('should allow withPageAuthRequired in app router', () => {
    async function Page() {
      return <span>Foo</span>;
    }
    expectTypeOf(withPageAuthRequired).toBeCallableWith(Page);
  });

  test('should allow withPageAuthRequired in app router with opts', () => {
    async function Page() {
      return <span>Foo</span>;
    }
    expectTypeOf(withPageAuthRequired).toBeCallableWith(Page, { returnTo: 'foo' });
  });

  test('should allow custom params in withPageAuthRequired', () => {
    async function Page({ params }: { params?: Record<string, string | string[]> }) {
      return <span>{typeof params}</span>;
    }
    expectTypeOf(withPageAuthRequired).toBeCallableWith(Page);
  });
});
