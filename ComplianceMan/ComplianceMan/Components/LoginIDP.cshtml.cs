using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Auth0.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Milbix.OAuthConnector.Core.Interface;
using Milbix.OAuthConnector.Core.Model;

namespace ComplianceMan.Components
{
    public class LoginIDPModel : PageModel
    {
        private IOAuthConnector _oauthConnector;
        private IConfiguration _configuration;
        public LoginIDPModel(IOAuthConnector oauthConnector, IConfiguration configuration)
        {
            _oauthConnector = oauthConnector;
            _configuration = configuration;
        }
        public async Task OnGetAsync(string provider)
        {
            if (provider == "Auth0")
            {
                await Login();
            }
            else {
                await Authenticate(provider);
            }
       
        }

        public async Task Login(string returnUrl = "/")
        {
            GeneratedChallenge generatedChallenge = _oauthConnector.GetAuthenticateChallange("Auth0");
            // Indicate here where Auth0 should redirect the user after a login.
            // Note that the resulting absolute Uri must be added to the
            // **Allowed Callback URLs** settings for the app in the Auth0 dashboard.


            await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, generatedChallenge.AuthenticationProperties);
        }

        [Authorize]
        public async Task<IActionResult> Logout()
        {
            var authenticationProperties = new LogoutAuthenticationPropertiesBuilder()
                // Indicate here where Auth0 should redirect the user after a logout.
                // Note that the resulting absolute Uri must be added in the
                // **Allowed Logout URLs** settings for the client.
                .WithRedirectUri(Url.Action("Index", "Home"))
                .Build();

            //await HttpContext.SignOutAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Index", "Home");
        }

        public async Task Authenticate(string provider)
        {
            string redirectUri = "/"; // Replace with your desired redirect URL


            if (provider == "AzureAD")
            {
                GeneratedChallenge generatedChallenge = _oauthConnector.GetAuthenticateChallange(provider);
                await HttpContext.ChallengeAsync(generatedChallenge.Provider, generatedChallenge.AuthenticationProperties);
            }
            else if (provider == "Google")
            {
                GeneratedChallenge generatedChallenge = _oauthConnector.GetAuthenticateChallange(provider);
                await HttpContext.ChallengeAsync(generatedChallenge.Provider, generatedChallenge.AuthenticationProperties);
            }
            else if (provider == "GitHub")
            {
                GeneratedChallenge generatedChallenge = _oauthConnector.GetAuthenticateChallange(provider);
                await HttpContext.ChallengeAsync(generatedChallenge.Provider, generatedChallenge.AuthenticationProperties);
            }
            else if (provider == "Milbix")
            {
                GeneratedChallenge generatedChallenge = _oauthConnector.GetAuthenticateChallange(provider);
                await HttpContext.ChallengeAsync(generatedChallenge.Provider, generatedChallenge.AuthenticationProperties);
            }
            else
            {
                // Invalid provider
            }
        }
    }
}
