import LoginHandler from './login';
import LogoutHandler from './logout';
import CallbackHandler from './callback';
import ProfileHandler, { refetchProfile } from './profile';
import SessionHandler from './session';
import RequireAuthentication from './require-authentication';
import TokenCache from './token-cache';

export default {
  CallbackHandler,
  LoginHandler,
  LogoutHandler,
  ProfileHandler,
  refetchProfile,
  SessionHandler,
  RequireAuthentication,
  TokenCache
};
