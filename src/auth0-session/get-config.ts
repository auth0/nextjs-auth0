import Joi from '@hapi/joi';
import clone from 'clone';
import { defaultState as getLoginState } from './hooks/get-login-state';
import { Config } from './config';

const paramsSchema = Joi.object({
  secret: Joi.alternatives([
    Joi.string().min(8),
    Joi.binary().min(8),
    Joi.array().items(Joi.string().min(8), Joi.binary().min(8))
  ]).required(),
  session: Joi.object({
    rolling: Joi.boolean().optional().default(true),
    rollingDuration: Joi.when(Joi.ref('rolling'), {
      is: true,
      then: Joi.number().integer().messages({
        'number.base': '"session.rollingDuration" must be provided an integer value when "session.rolling" is true'
      }),
      otherwise: Joi.boolean().valid(false).messages({
        'any.only': '"session.rollingDuration" must be false when "session.rolling" is disabled'
      })
    })
      .optional()
      .default((parent) => (parent.rolling ? 24 * 60 * 60 : false)), // 1 day when rolling is enabled, else false
    absoluteDuration: Joi.when(Joi.ref('rolling'), {
      is: false,
      then: Joi.number().integer().messages({
        'number.base': '"session.absoluteDuration" must be provided an integer value when "session.rolling" is false'
      }),
      otherwise: Joi.alternatives([Joi.number().integer(), Joi.boolean().valid(false)])
    })
      .optional()
      .default(7 * 24 * 60 * 60), // 7 days,
    name: Joi.string().token().optional().default('appSession'),
    cookie: Joi.object({
      domain: Joi.string().optional(),
      transient: Joi.boolean().optional().default(false),
      httpOnly: Joi.boolean().optional().default(true),
      sameSite: Joi.string().valid('lax', 'strict', 'none').optional().default('lax'),
      secure: Joi.boolean().optional(),
      path: Joi.string().uri({ relativeOnly: true }).optional()
    })
      .default()
      .unknown(false)
  })
    .default()
    .unknown(false),
  auth0Logout: Joi.boolean().optional().default(false),
  authorizationParams: Joi.object({
    response_type: Joi.string().optional().valid('id_token', 'code id_token', 'code').default('id_token'),
    scope: Joi.string()
      .optional()
      .pattern(/\bopenid\b/, 'contains openid')
      .default('openid profile email'),
    response_mode: Joi.string()
      .optional()
      .when('response_type', {
        is: 'code',
        then: Joi.valid('query', 'query'),
        otherwise: Joi.valid('form_post').default('form_post')
      })
  })
    .optional()
    .unknown(true)
    .default(),
  baseURL: Joi.string().uri().required(),
  clientID: Joi.string().required(),
  clientSecret: Joi.string()
    .when(
      Joi.ref('authorizationParams.response_type', {
        adjust: (value) => value && value.includes('code')
      }),
      {
        is: true,
        then: Joi.string().required().messages({
          'any.required': '"clientSecret" is required for a response_type that includes code'
        })
      }
    )
    .when(
      Joi.ref('idTokenSigningAlg', {
        adjust: (value) => value && value.startsWith('HS')
      }),
      {
        is: true,
        then: Joi.string().required().messages({
          'any.required': '"clientSecret" is required for ID tokens with HMAC based algorithms'
        })
      }
    ),
  clockTolerance: Joi.number().optional().default(60),
  enableTelemetry: Joi.boolean().optional().default(true),
  errorOnRequiredAuth: Joi.boolean().optional().default(false),
  attemptSilentLogin: Joi.boolean().optional().default(false),
  getLoginState: Joi.function()
    .optional()
    .default(() => getLoginState),
  identityClaimFilter: Joi.array()
    .optional()
    .default(['aud', 'iss', 'iat', 'exp', 'nbf', 'nonce', 'azp', 'auth_time', 's_hash', 'at_hash', 'c_hash']),
  idpLogout: Joi.boolean()
    .optional()
    .default((parent) => parent.auth0Logout || false),
  idTokenSigningAlg: Joi.string().insensitive().not('none').optional().default('RS256'),
  issuerBaseURL: Joi.string().uri().required(),
  legacySameSiteCookie: Joi.boolean().optional().default(true),
  authRequired: Joi.boolean().optional().default(true),
  routes: Joi.object({
    login: Joi.alternatives([Joi.string().uri({ relativeOnly: true }), Joi.boolean().valid(false)]).default('/login'),
    logout: Joi.alternatives([Joi.string().uri({ relativeOnly: true }), Joi.boolean().valid(false)]).default('/logout'),
    callback: Joi.string().uri({ relativeOnly: true }).default('/callback'),
    postLogoutRedirect: Joi.string().uri({ allowRelative: true }).default('')
  })
    .default()
    .unknown(false)
});

export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends Array<infer I> ? Array<DeepPartial<I>> : DeepPartial<T[P]>;
};

export type ConfigParameters = DeepPartial<Config>;

export const get = (params?: ConfigParameters): Config => {
  let config = typeof params === 'object' ? clone(params) : {}; // @TODO need clone?
  config = {
    secret: process.env.SECRET,
    issuerBaseURL: process.env.ISSUER_BASE_URL,
    baseURL: process.env.BASE_URL,
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    ...config
  };

  const paramsValidation = paramsSchema.validate(config);
  if (paramsValidation.error) {
    throw new TypeError(paramsValidation.error.details[0].message);
  }

  return paramsValidation.value;
};
