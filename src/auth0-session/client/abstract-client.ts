import { Config } from '../config';
import { Auth0Request } from '../http';

export type Telemetry = {
  name: string;
  version: string;
};

export interface CallbackParamsType {
  access_token?: string;
  code?: string;
  error?: string;
  error_description?: string;
  error_uri?: string;
  expires_in?: string;
  id_token?: string;
  state?: string;
  token_type?: string;
  session_state?: string;
  response?: string;

  [key: string]: any;
}

export interface CallbackExtras {
  exchangeBody?: Record<string, any>;
  clientAssertionPayload?: Record<string, any>;
}

export interface OpenIDCallbackChecks {
  max_age?: number;
  nonce?: string;
  response_type: string;
  state?: string;
  code_verifier?: string;
}

export interface TokenEndpointResponse {
  access_token?: string;
  token_type?: string;
  id_token?: string;
  refresh_token?: string;
  scope?: string;
  expires_in?: number;
  [key: string]: unknown;
}

export interface EndSessionParameters {
  id_token_hint?: string;
  post_logout_redirect_uri: string;
  state?: string;
  client_id?: string;
  logout_hint?: string;

  [key: string]: any;
}

export type ClientAuthMethod = 'client_secret_basic' | 'client_secret_post' | 'private_key_jwt' | 'none';

export interface AuthorizationParameters {
  acr_values?: string;
  audience?: string;
  claims_locales?: string;
  client_id?: string;
  code_challenge_method?: string;
  code_challenge?: string;
  display?: string;
  id_token_hint?: string;
  login_hint?: string;
  max_age?: number;
  nonce?: string;
  prompt?: string;
  redirect_uri?: string;
  registration?: string;
  request_uri?: string;
  request?: string;
  resource?: string | string[];
  response_mode?: string;
  response_type?: string;
  scope?: string;
  state?: string;
  ui_locales?: string;

  [key: string]: unknown;
}

export type IssuerMetadata = {
  issuer: string;
  jwks_uri?: string;
};

export abstract class AbstractClient {
  constructor(protected config: Config, protected telemetry: Telemetry) {}
  abstract authorizationUrl(parameters: Record<string, unknown>): Promise<string>;
  abstract callbackParams(req: Auth0Request, expectedState: string): Promise<URLSearchParams>;
  abstract callback(
    redirectUri: string,
    parameters: URLSearchParams,
    checks: OpenIDCallbackChecks,
    extras: CallbackExtras
  ): Promise<TokenEndpointResponse>;
  abstract endSessionUrl(parameters: EndSessionParameters): Promise<string>;
  abstract userinfo(accessToken: string): Promise<Record<string, unknown>>;
  abstract refresh(
    refreshToken: string,
    extras: { exchangeBody?: Record<string, any> }
  ): Promise<TokenEndpointResponse>;
  abstract generateRandomCodeVerifier(): string;
  abstract generateRandomNonce(): string;
  abstract calculateCodeChallenge(codeVerifier: string): Promise<string> | string;
  abstract getIssuerMetadata(): Promise<IssuerMetadata>;
}

export type GetClient = (config: Config) => Promise<AbstractClient>;
