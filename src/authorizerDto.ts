export interface TokenHeader {
  kid: string
  alg: string
}

export interface PublicKey {
  alg: string
  e: string
  kid: string
  kty: string
  n: string
  use: string
}

export interface Claim {
  token_use: string
  iss: string
  aud: string
  exp: number
  auth_time: number
  client_id: string
}

export interface AuthResponse {
  principalId: string
  policyDocument: PolicyDocument
  context
}

export interface PolicyDocument {
  Version: string
  Statement: AuthStatement[]
}

export interface AuthStatement {
  Action: string
  Effect: string
  Resource: string
}

export interface IdTokenContent {
  userPoolId: string
  userPoolClientId: string
  prefferedRole: string
  roles: string[]
  username: string
}

export interface JWTToken {
  /**
   * Issuer of token (URL)
   */
  iss: string

  /**
   * Issued at time (UNIX Timestamp)
   */
  iat: number

  /**
   * Expiry time (UNIX Timestamp)
   */
  exp: number

  [claim: string]: unknown
}

export interface InternalJWTTokenContent extends JWTToken {
  /**
   * AWS ARN for role or user calling
   */
  callerIdentity: string

  /**
   * List relevant policydocuments
   */
  policies: PolicyDocument[]
}
