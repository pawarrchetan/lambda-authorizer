import Log from '@dazn/lambda-powertools-logger'
import { metricScope, Unit } from 'aws-embedded-metrics'
import {
  APIGatewayRequestAuthorizerEvent,
  APIGatewayAuthorizerCallback,
  Context
} from 'aws-lambda'
import * as AWSXRay from 'aws-xray-sdk'
import { Base64 } from 'js-base64'

import * as AuthConst from './authorizerConstants'
import { InternalJWTTokenContent } from './authorizerDto'
import * as AuthUtils from './authorizerUtils'
import { mergePolicies } from './iamUtils'

AWSXRay.setLogger(Log)

function logError(error, targetArn, callback, metrics) {
  const errorMessage = JSON.stringify({
    message: error.message,
    'target-resource': targetArn
  })
  error['statusCode'] = error['statusCode'] || 500
  error['target-resource'] = targetArn

  Log.error(errorMessage, error, error)

  if (error['metricMessage']) {
    metrics.putMetric(error['metricMessage'], 1, Unit.Count)
  }

  callback('Unauthorized')
}

/**
 * Main entrypoint for custom authorizer
 *
 * @param event
 * @param _context
 * @param callback
 */
export const authorize = metricScope(
  (metrics) => async (
    event: APIGatewayRequestAuthorizerEvent,
    _context: Context,
    callback: APIGatewayAuthorizerCallback
  ) => {
    Log.debug('Authorizer process ...')

    metrics.setNamespace('Authorizer')
    metrics.putDimensions({ Service: 'Authorizer' })

    try {
      // decide which flow to use, combined IdAccessToken or JWT
      const authorizationHeader =
        event.headers[AuthConst.TOKEN_HEADER_PARAM] ||
        event.headers[AuthConst.TOKEN_HEADER_PARAM.toLowerCase()]

      const token = getBearerToken(authorizationHeader)

      if (AuthUtils.isJwtToken(token)) {
        await authorizeJwtToken({
          token,
          callback
        })
      } else {
        await authorizeIdAccessToken({
          token,
          callback
        })
      }

      metrics.putMetric('authorized', 1, Unit.Count)
    } catch (error) {
      logError(error, event.methodArn, callback, metrics)

      return
    }
  }
)

/**
 * Authorize request with a JWT token from a trusted issuer
 */
const authorizeJwtToken = async ({
  token,
  callback
}: {
  token: string
  callback: APIGatewayAuthorizerCallback
}) => {
  if (!AuthUtils.tokenIssuerIsTrusted(token)) {
    throwInvalidRequest('token issuer not trusted')
  }

  const payload = await AuthUtils.verifyJwtTokenWithJwks(token)

  const { policies, callerIdentity } = payload as InternalJWTTokenContent

  if (!policies) {
    throwInvalidRequest('policy missing from token')
  }

  callback(null, {
    principalId: callerIdentity,
    policyDocument: mergePolicies(policies)
  })
}

/**
 * Authorize request with custom base64 formatted
 */
const authorizeIdAccessToken = async ({
  token,
  callback
}: {
  token: string
  callback: APIGatewayAuthorizerCallback
}) => {
  const { idtoken, accesstoken } = getIdAccessTokens(token)

  const idTokenContent = AuthUtils.getIdTokenContent(idtoken)

  // check for userPoolId and preferred role from idtoken
  validateTokenContent(idTokenContent)

  // verify Tokens
  await AuthUtils.verifyTokens(idtoken, accesstoken, idTokenContent)

  // validate userpool and get policy
  const policy = await AuthUtils.getPolicy(idTokenContent)

  return callback(null, policy)
}

/**
 * Extracts the token part from bearer authorization header and throws errors if this fails
 */
const getBearerToken = (authorizationHeader: string) => {
  if (!authorizationHeader) {
    throwInvalidRequest('Parameter is missing: Authorization.')
  }

  // We split the components of the authorization header
  const authorizationHeaderParts = authorizationHeader.split(' ')
  if (authorizationHeaderParts.length != 2) {
    throwInvalidRequest('malformed authorization header')
  }

  // We verify that the header is of type Bearer
  if (authorizationHeaderParts[0].toLowerCase() != 'bearer') {
    throwInvalidRequest('unsupported token type')
  }

  return authorizationHeaderParts[1]
}

/**
 * validates and decode header param and return id and acces tokens
 */
const getIdAccessTokens = (token: string) => {
  let jwtToken
  try {
    jwtToken = JSON.parse(Base64.decode(token))
  } catch (error) {
    throwInvalidRequest('invalid tokens')
  }

  if (!jwtToken['idtoken'] || !jwtToken['accesstoken']) {
    throwInvalidRequest('missing credentials')
  }

  return {
    idtoken: jwtToken['idtoken'],
    accesstoken: jwtToken['accesstoken']
  }
}

/**
 * checks if claim contains required attributes
 * @param idtokenContent
 */
const validateTokenContent = (idtokenContent) => {
  if (!idtokenContent.userPoolId) {
    throwInvalidRequest('Cognito pool not found')
  }

  if (!idtokenContent.prefferedRole) {
    throwInvalidRequest(
      'Cognito roles or prefferedRole configuration not found'
    )
  }
}

const throwInvalidRequest = (message) => {
  const error = new Error(message)
  error['statusCode'] = 400
  error['metricMessage'] = 'invalidRequest'
  throw error
}
