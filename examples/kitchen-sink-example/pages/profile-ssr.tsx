import { withPageAuthRequired } from '@auth0/nextjs-auth0';
import { InferGetServerSidePropsType } from 'next';

export const getServerSideProps = withPageAuthRequired({
  getServerSideProps: async ({ query, req, res }) => {
    if ((query.foo = 'bar')) {
      return { notFound: true };
    }
    return { props: { hello: 'world' } };
  }
});

export type Props = InferGetServerSidePropsType<typeof getServerSideProps>;
