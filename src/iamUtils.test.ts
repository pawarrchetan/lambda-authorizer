import { PolicyDocument } from './authorizerDto'
import { mergePolicies } from './iamUtils'

describe('iamUtils', () => {
  describe('mergePolicies', () => {
    it('should combine statements', () => {
      const policy1: PolicyDocument = {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Action: 'execute-api:Invoke',
            Resource: 'res1'
          }
        ]
      }

      const policy2: PolicyDocument = {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Action: 'execute-api:Invoke',
            Resource: 'res2'
          },
          {
            Effect: 'Allow',
            Action: 'execute-api:Invoke',
            Resource: 'res3'
          }
        ]
      }

      expect(mergePolicies([policy1, policy2])).toMatchObject({
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Action: 'execute-api:Invoke',
            Resource: 'res1'
          },
          {
            Effect: 'Allow',
            Action: 'execute-api:Invoke',
            Resource: 'res2'
          },
          {
            Effect: 'Allow',
            Action: 'execute-api:Invoke',
            Resource: 'res3'
          }
        ]
      })
    })
  })
})
