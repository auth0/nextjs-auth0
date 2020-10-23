import { IdTokenClaims, TokenSet, TokenSetParameters } from 'openid-client';
import { Config } from './config';
import { ClientFactory } from './client';

export default class Session {
  public tokenSet: TokenSet;
  public user: Partial<IdTokenClaims>;
  constructor(
    session: TokenSetParameters,
    config: Config,
    private getClient: ClientFactory,
    public createdAt = Date.now()
  ) {
    this.tokenSet = new TokenSet(session);
    const { identityClaimFilter } = config;
    const { idTokenClaims: user } = this;
    identityClaimFilter.forEach((claim) => {
      delete user[claim];
    });
    this.user = user;
  }

  isAuthenticated() {
    return !!this.idTokenClaims;
  }

  get idToken() {
    return this.tokenSet.id_token;
  }

  get refreshToken() {
    return this.tokenSet.refresh_token;
  }

  get accessToken() {
    const { access_token, token_type, expires_in } = this.tokenSet;

    return {
      access_token,
      token_type,
      expires_in,
      isExpired: () => this.tokenSet.expired(),
      refresh: async () => {
        const client = await this.getClient();
        const oldTokenSet = this.tokenSet;
        const newTokenSet = await client.refresh(oldTokenSet);

        this.tokenSet = new TokenSet({
          id_token: newTokenSet.id_token,
          access_token: newTokenSet.access_token,
          // If no new refresh token assume the current refresh token is valid.
          refresh_token: newTokenSet.refresh_token || oldTokenSet.refresh_token,
          token_type: newTokenSet.token_type,
          expires_at: newTokenSet.expires_at
        });

        return this.accessToken;
      }
    };
  }

  get idTokenClaims() {
    return this.tokenSet.claims();
  }

  static fromString(str: string, config: Config, getClient: ClientFactory, createdAt?: number) {
    return new Session(JSON.parse(str), config, getClient, createdAt);
  }

  toString() {
    const { id_token, access_token, refresh_token, token_type, expires_at } = this.tokenSet;
    return JSON.stringify({
      id_token,
      access_token,
      refresh_token,
      token_type,
      expires_at
    });
  }
}
