using System;
using System.Net.Http;
using IdentityModel.Client;

namespace IdentityServer3.AccessTokenValidation
{
    public class Rfc2617IntrospectionClient : IntrospectionClient
    {
        public Rfc2617IntrospectionClient(string endpoint, string clientId = "", string clientSecret = "", HttpMessageHandler innerHttpMessageHandler = null, AuthenticationHeaderStyle authenticationHeaderStyle = AuthenticationHeaderStyle.Rfc6749) 
            : base(endpoint, clientId, clientSecret, innerHttpMessageHandler)
        {
            if (!string.IsNullOrWhiteSpace(clientId) && !string.IsNullOrWhiteSpace(clientSecret))
            {
                if (authenticationHeaderStyle == AuthenticationHeaderStyle.Rfc6749)
                {
                    this.Client.SetBasicAuthenticationOAuth(clientId, clientSecret);
                }
                else if (authenticationHeaderStyle == AuthenticationHeaderStyle.Rfc2617)
                {
                    this.Client.SetBasicAuthentication(clientId, clientSecret);
                }
                else
                {
                    throw new InvalidOperationException("Invalid basic authentication header style");
                }

            }
        }

        public enum AuthenticationHeaderStyle
        {
            Rfc6749,
            Rfc2617
        }
    }
}