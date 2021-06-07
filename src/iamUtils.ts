import { PolicyDocument, Statement } from 'aws-lambda'

export const mergePolicies = (policies: PolicyDocument[]): PolicyDocument => {
  const Statement: Statement[] = []
  for (const policy of policies) {
    Statement.push(...policy.Statement)
  }

  return {
    Version: '2012-10-17',
    Statement
  }
}
