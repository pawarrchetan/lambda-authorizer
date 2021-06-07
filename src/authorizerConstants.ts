// only for local testing purposes
export const IS_OFFLINE = process.env.IS_OFFLINE === 'true'

// table name
export const DYNAMODB_TABLE = process.env.DYNAMODB_TABLE

// cognito region Id
export const REGION_ID = process.env.AWS_REGION_ID
  ? process.env.AWS_REGION_ID
  : 'eu-central-1'

// Cognito issuer url extenstion
export const OIDC_ISSUER_PATH = '/.well-known/jwks.json'

// authorization header the idtoken and accesstoken can be grabbed from here
export const TOKEN_HEADER_PARAM = 'Authorization'

// JWT claim atrributes
export const JWT_USERPOOL_ID_ATTRIBUTE = 'userPoolId'
export const JWT_ISSUER_ATTRIBUTE = 'iss'
export const JWT_AUDIENCE_ATTRIBUTE = 'aud'
export const JWT_PREFERED_ROLE_ATTRIBUTE = 'cognito:preferred_role'
export const JWT_ROLES_ATTRIBUTE = 'cognito:roles'
export const JWT_USERNAME_ATTRIBUTE = 'cognito:username'

export const AUTHORIZED_POLICY_NAME = 'CognitoAuthorizedPolicy'
export const STATUS_CODE_FORBIDDEN = 403
