using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using Amazon.Lambda.APIGatewayEvents;
using Amazon.Lambda.Core;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Serialization;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.Json.JsonSerializer))]

namespace LetsAuthorize
{
    public class Function
    {
        public APIGatewayCustomAuthorizerResponse FunctionHandler(APIGatewayCustomAuthorizerRequest input,
            ILambdaContext context)
        {
            var ok = false;

            var handler = new JsonWebTokenHandler();
            var decoded = handler.ReadJsonWebToken(input.AuthorizationToken);
            if (decoded.Subject == "user1")
            {
                ok = true;
            }

            return new APIGatewayCustomAuthorizerResponse()
            {
                PrincipalID = decoded.Subject,
                PolicyDocument = new APIGatewayCustomAuthorizerPolicy()
                {
                    Statement = new List<APIGatewayCustomAuthorizerPolicy.IAMPolicyStatement>()
                    {
                        new APIGatewayCustomAuthorizerPolicy.IAMPolicyStatement()
                        {
                            Action = new HashSet<string>() {"execute-api:Invoke"},
                            Effect = ok ? "Allow" : "Deny",
                            Resource = new HashSet<string>() {input.MethodArn}
                        }
                    },
                    Version = "2012-10-17"
                }
            };
        }
    }
}