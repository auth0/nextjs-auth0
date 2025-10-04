import { Auth0Provider } from '@auth0/nextjs-auth0';

export const mockUser = {
  email: 'foo@example.com',
  email_verified: true,
  name: 'foo',
  nickname: 'foo',
  picture: 'foo.jpg',
  sub: '1',
  updated_at: null
};

export const withAuth0Provider = ({ user, profileUrl } = {}) => {
  return props => <Auth0Provider {...props} user={user} profileUrl={profileUrl} />;
};
