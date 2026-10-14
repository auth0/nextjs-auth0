export interface Routes {
  login: string;
  logout: string;
  callback: string;
  profile: string;
  accessToken: string;
  federatedDomain: string;
  backChannelLogout: string;
  connectAccount: string;
  mfaAuthenticators: string;
  mfaChallenge: string;
  mfaVerify: string;
  mfaAssociate: string;
  passwordlessStart: string;
  passwordlessVerify: string;
  passwordlessDbOtpChallenge: string;
  passwordlessDbGetToken: string;
  passkeyRegister: string;
  passkeyChallenge: string;
  passkeyGetToken: string;
  passkeyEnrollmentChallenge: string;
  passkeyEnrollmentVerify: string;
  anonymousSession?: string;
  anonymousSessionLogout?: string;
}

export type RoutesOptions = Partial<Routes>;
