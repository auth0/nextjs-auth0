import { GetServerSidePropsContext } from 'next';

export const assertReqRes = (req: unknown, res: unknown): void => {
  if (!req) {
    throw new Error('Request is not available');
  }
  if (!res) {
    throw new Error('Response is not available');
  }
};

export const assertCtx = ({ req, res }: GetServerSidePropsContext<any>): void => {
  assertReqRes(req, res);
};
