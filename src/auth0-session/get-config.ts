import Joi from 'joi';
import { getLoginState } from './hooks/get-login-state';
import { Config } from './config';

const isHttps = /^https:/i;

const paramsSchema = Joi.object({
  secret: Joi.alternatives([Joi.string().min(8), Joi.array().items(Joi.string().min(8))]).required(),
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
    autoSave: Joi.boolean().optional().default(true),
    name: Joi.string().token().optional().default('appSession'),
    store: Joi.object().optional(),
    genId: Joi.function().maxArity(2).when(Joi.ref('store'), { then: Joi.required() }),
    storeIDToken: Joi.boolean().optional().default(true),
    cookie: Joi.object({
      domain: Joi.string().optional(),
      transient: Joi.boolean().optional().default(false),
      httpOnly: Joi.boolean().optional().default(true),
      sameSite: Joi.string().valid('lax', 'strict', 'none').optional().default('lax'),
      secure: Joi.when(Joi.ref('/baseURL'), {
        is: Joi.string().pattern(isHttps),
        then: Joi.boolean().valid(true).default(true).messages({
          'any.only': 'Cookies must be secure when base url is https.'
        }),
        otherwise: Joi.boolean().valid(false).default(false).messages({
          'any.only': 'Cookies set with the `Secure` property wont be attached to http requests'
        })
      }),
      path: Joi.string().uri({ relativeOnly: true }).optional()
    })
      .default()
      .unknown(false)
  })
    .default()
    .unknown(false),
  auth0Logout: Joi.boolean().optional(),
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
        then: Joi.valid('query', 'form_post'),
        otherwise: Joi.valid('form_post').default('form_post')
      })
  })
    .optional()
    .unknown(true)
    .default(),
  baseURL: Joi.string()
    .uri()
    .required()
    .when(Joi.ref('authorizationParams.response_mode'), {
      is: 'form_post',
      then: Joi.string()
        .pattern(isHttps)
        .rule({
          warn: true,
          message:
            "Using 'form_post' for response_mode may cause issues for you logging in over http, " +
            'see https://github.com/auth0/express-openid-connect/blob/master/FAQ.md'
        })
    }),
  clientID: Joi.string().required(),
  clientSecret: Joi.string()
    .when(
      Joi.ref('clientAuthMethod', {
        adjust: (value) => value && value.includes('client_secret')
      }),
      {
        is: true,
        then: Joi.string().required().messages({
          'any.required': '"clientSecret" is required for the clientAuthMethod {{clientAuthMethod}}'
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
  httpTimeout: Joi.number().optional().default(5000),
  enableTelemetry: Joi.boolean().optional().default(true),
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
  routes: Joi.object({
    callback: Joi.string().uri({ relativeOnly: true }).required(),
    postLogoutRedirect: Joi.string().uri({ allowRelative: true }).default('')
  })
    .default()
    .unknown(false),
  clientAuthMethod: Joi.string()
    .valid('client_secret_basic', 'client_secret_post', 'client_secret_jwt', 'private_key_jwt', 'none')
    .optional()
    .default((parent) => {
      if (parent.authorizationParams.response_type === 'id_token') {
        return 'none';
      }

      if (parent.clientAssertionSigningKey) {
        return 'private_key_jwt';
      }

      return 'client_secret_basic';
    })
    .when(
      Joi.ref('authorizationParams.response_type', {
        adjust: (value) => value && value.includes('code')
      }),
      {
        is: true,
        then: Joi.string().invalid('none').messages({
          'any.only': 'Public code flow clients are not supported.'
        })
      }
    ),
  clientAssertionSigningKey: Joi.any()
    .optional()
    .when(Joi.ref('clientAuthMethod'), {
      is: 'private_key_jwt',
      then: Joi.any().required().messages({
        'any.required': '"clientAssertionSigningKey" is required for a "clientAuthMethod" of "private_key_jwt"'
      })
    }),
  clientAssertionSigningAlg: Joi.string()
    .optional()
    .valid('RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES256K', 'ES384', 'ES512', 'EdDSA')
});

export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends Array<infer I> ? Array<DeepPartial<I>> : DeepPartial<T[P]>;
};

export type ConfigParameters = DeepPartial<Config>;

export const get = (params: ConfigParameters = {}): Config => {
  const { value, error, warning } = paramsSchema.validate(params, { allowUnknown: true });
  if (error) {
    throw new TypeError(error.details[0].message);
  }
  if (warning) {
    console.warn(warning.message);
  }

  return value;
};
