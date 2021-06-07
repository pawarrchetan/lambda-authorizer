import Log from '@dazn/lambda-powertools-logger'
import { APIGatewayAuthorizerResult } from 'aws-lambda'
import { IAM, CognitoIdentityServiceProvider } from 'aws-sdk'
import * as AWSXRay from 'aws-xray-sdk'
import * as Axios from 'axios'
import jsonwebtoken from 'jsonwebtoken'
import jwkToBuffer from 'jwk-to-pem'
import jwksClient from 'jwks-rsa'

import * as AuthConst from './authorizerConstants'
import * as AuthDTO from './authorizerDto'
import { JWTToken } from './authorizerDto'

/**
 * Getter defined in order to successfully mock AWS services using aws-sdk-mock
 */
const getIam = (() => {
  let iam: IAM

  return () => {
    if (!iam) {
      iam = AWSXRay.captureAWSClient(new IAM({ apiVersion: '2010-05-08' }))
    }

    return iam
  }
})()

/**
 * Getter defined in order to successfully mock AWS services using aws-sdk-mock
 */
const getCognitoIdentityServiceProvider = (() => {
  let cognitoIdentityServiceProvider: CognitoIdentityServiceProvider

  return () => {
    if (!cognitoIdentityServiceProvider) {
      cognitoIdentityServiceProvider = AWSXRay.captureAWSClient(
        new CognitoIdentityServiceProvider()
      )
    }

    return cognitoIdentityServiceProvider
  }
})()

const verifyWebToken = jsonwebtoken.verify.bind(jsonwebtoken)

const getUserPoolIdFromIssuer = (jwtpayload) => {
  const issuer = jwtpayload[AuthConst.JWT_ISSUER_ATTRIBUTE] || ''

  return issuer.substring(issuer.lastIndexOf('/') + 1)
}

const getIdTokenContent = (idToken) => {
  const claims = {} as AuthDTO.IdTokenContent

  const tokenSections = (idToken || '').split('.')
  if (tokenSections.length < 2) {
    handleResponseError(
      'requested token is invalid',
      'invalidTokenContent',
      AuthConst.STATUS_CODE_FORBIDDEN
    )
  }
  const jwtPayload = Buffer.from(tokenSections[1], 'base64').toString('utf8')
  const claim = JSON.parse(jwtPayload) as AuthDTO.Claim
  // const header = JSON.parse(jwtPayload) as AuthDTO.TokenHeader

  claims.userPoolId = getUserPoolIdFromIssuer(claim)
  claims.userPoolClientId = claim.aud

  // if the user does not belong to a group in the user pool:
  // The identity token does not contain `"cognito:roles"` and `"cognito:preferred_role"`
  claims.prefferedRole = claim[AuthConst.JWT_PREFERED_ROLE_ATTRIBUTE]
  claims.roles = claim[AuthConst.JWT_ROLES_ATTRIBUTE]
  claims.username = claim[AuthConst.JWT_USERNAME_ATTRIBUTE]
  Log.debug('found claims', { claims })

  return claims
}

const verifyToken = async (token, publicKeys, cognitoIssuer) => {
  return new Promise((resolve) => {
    const tokenSections = (token || '').split('.')

    if (tokenSections.length < 2) {
      handleResponseError(
        'requested token is invalid',
        'invalidToken',
        AuthConst.STATUS_CODE_FORBIDDEN
      )
    }
    const jwtHeader = Buffer.from(tokenSections[0], 'base64').toString('utf8')

    const header = JSON.parse(jwtHeader) as AuthDTO.TokenHeader

    // get used KID in this JWT FROM JWKS (json web keys)
    const usedKey = publicKeys.data.keys.filter((it) => it.kid == header.kid)
    if (usedKey.length == 0) {
      handleResponseError(
        'claim made for unknown kid',
        'invalidToken',
        AuthConst.STATUS_CODE_FORBIDDEN
      )
    }
    let pem = ''
    try {
      pem = jwkToBuffer(usedKey[0])
    } catch (error) {
      handleResponseError(
        error.message,
        'invalidToken',
        AuthConst.STATUS_CODE_FORBIDDEN
      )
    }
    const claim = verifyWebToken(token, pem) as AuthDTO.Claim

    if (claim.iss !== cognitoIssuer) {
      handleResponseError(
        'claim issuer is invalid',
        'invalidToken',
        AuthConst.STATUS_CODE_FORBIDDEN
      )
    }

    const currentSeconds = Math.floor(new Date().valueOf() / 1000)

    if (
      !claim.exp ||
      currentSeconds > claim.exp ||
      currentSeconds < claim.auth_time
    ) {
      Log.debug('Token is expired or invalid')
      handleResponseError(
        'Token is expired or invalid',
        'invalidToken',
        AuthConst.STATUS_CODE_FORBIDDEN
      )
    }
    resolve('valid')
  })
}

const verifyTokens = async (idtoken, accessToken, idTokenContent) => {
  const cognitoIssuer = `https://cognito-idp.${AuthConst.REGION_ID}.amazonaws.com/${idTokenContent.userPoolId}`
  const publicKeys = await getpublicKeys(cognitoIssuer)
  try {
    await Promise.all([
      verifyToken(idtoken, publicKeys, cognitoIssuer),
      verifyToken(accessToken, publicKeys, cognitoIssuer)
    ])
  } catch (error) {
    handleResponseError(
      error.message,
      'encryptionKeyNotFound',
      AuthConst.STATUS_CODE_FORBIDDEN
    )
  }
}

const getPolicy = async (idTokenContent) => {
  try {
    const results = await Promise.all([
      isValidUserpool(idTokenContent),
      getRolePolicy(idTokenContent)
    ])

    const authResponse = {} as APIGatewayAuthorizerResult
    authResponse.principalId = idTokenContent.username
    authResponse.policyDocument = JSON.parse(
      decodeURIComponent(results[1].PolicyDocument)
    )

    Log.debug('added policy document to response:', authResponse.policyDocument)
    authResponse.context = {
      username: idTokenContent.username,
    }

    return authResponse
  } catch (error) {
    handleResponseError(
      error.message,
      'IAMPolicyReuestFailed',
      error['statusCode']
    )
  }
}

const getpublicKeys = async (cognitoIssuer) => {
  try {
    return await Axios.default.get<AuthDTO.PublicKey>(
      cognitoIssuer + AuthConst.OIDC_ISSUER_PATH
    )
  } catch (error) {
    handleResponseError(
      `get JWKS failed for Issuer: ${cognitoIssuer} :  ${JSON.stringify(
        error
      )}`,
      'encryptionKeyNotFound',
      error.status
    )
    //        'encryptionKeyNotFound',
  }
}
/**
 * try to get infos about the userpool. If this userpool is not part of
 * the resources in this environment the methode throws error
 */
const isValidUserpool = async (params: AuthDTO.IdTokenContent) => {
  const request: CognitoIdentityServiceProvider.Types.DescribeUserPoolClientRequest = {
    ClientId: params.userPoolClientId,
    UserPoolId: params.userPoolId
  }
  try {
    return await getCognitoIdentityServiceProvider()
      .describeUserPoolClient(request)
      .promise()
  } catch (error) {
    handleResponseError(
      'provided user pool is unknown',
      'unidentifiedPool',
      AuthConst.STATUS_CODE_FORBIDDEN
    )
  }
}

const getRolePolicy = async (idTokenContent) => {
  Log.debug(
    'looking for the policies from role: ' + idTokenContent.prefferedRole
  )
  const auxRole = idTokenContent.prefferedRole || ''
  const roleName = auxRole.substring(auxRole.lastIndexOf('/') + 1)
  try {
    Log.debug('get policy names for the given role: ', roleName)
    const rolePolicies: IAM.Types.ListRolePoliciesResponse = await getIam()
      .listRolePolicies({ RoleName: roleName })
      .promise()

    if (!rolePolicies.PolicyNames || rolePolicies.PolicyNames.length == 0) {
      Log.debug('No Policy found for Role: ' + roleName)

      return null
    }
    const policyRequest = {
      RoleName: roleName,
      PolicyName: rolePolicies.PolicyNames[0]
    }

    Log.debug(
      'get policy document for the given role: ' +
        policyRequest.RoleName +
        ' and policy: ' +
        policyRequest.PolicyName
    )

    return await getIam().getRolePolicy(policyRequest).promise()
  } catch (error) {
    handleResponseError(
      'Failed to get policy from IAM',
      'IAMPolicyReuestFailed',
      error['statusCode']
    )
  }
}

const handleResponseError = (
  errorMessage: string,
  metricMessage?: string,
  errorStatusCode?: number
) => {
  const errorToThrow = new Error(errorMessage)
  errorToThrow['statusCode'] = errorStatusCode || 500
  errorToThrow['metricMessage'] = metricMessage
  throw errorToThrow
}

/**
 * Helper method to check whether a string is a JWT token
 */
const isJwtToken = (token: string): boolean =>
  Boolean(jsonwebtoken.decode(token))

/**
 * Verify token using JWKS from issuer
 */
const verifyJwtTokenWithJwks = async (token: string): Promise<JWTToken> => {
  const { iss } = jsonwebtoken.decode(token) as JWTToken

  // create client to get jwks
  const client = jwksClient({
    jwksUri: `${iss}${AuthConst.OIDC_ISSUER_PATH}`
  })

  // verify token with jwks
  const payload = await new Promise((resolve, reject) =>
    jsonwebtoken.verify(
      token,
      (header, cb) => {
        client.getSigningKey(header.kid, (_, key) => {
          const signingKey = key.getPublicKey()
          cb(null, signingKey)
        })
      },
      (err, payload) => {
        if (err) reject(err)
        resolve(payload)
      }
    )
  )

  return payload as JWTToken
}

export const tokenIssuerIsTrusted = (token: string) => {
  const { iss } = jsonwebtoken.decode(token) as JWTToken

  const trustedIssuers = [process.env.INTERNAL_AUTH_ISSUER]

  return trustedIssuers.includes(iss)
}

export {
  verifyJwtTokenWithJwks,
  getIdTokenContent,
  verifyTokens,
  getPolicy,
  isValidUserpool,
  isJwtToken
}
