using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using DualAuthCoreExample.Auth;
using DualAuthCoreExample.Helpers;
using DualAuthCoreExample.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;

namespace DualAuthCoreExample.Controllers.Api
{
    [Produces("application/json")]
    [Route("api/auth")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Policy = "ApiUser")]
    public class AuthController : Controller
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly IJwtFactory jwtFactory;
        private readonly JsonSerializerSettings serializerSettings;
        private readonly JwtIssuerOptions jwtOptions;
        private readonly IOptions<Options.VersionOptions> versionStrings;

        public AuthController(
            UserManager<ApplicationUser> userManager,
            IJwtFactory jwtFactory,
            IOptions<JwtIssuerOptions> jwtOptions,
            IOptions<Options.VersionOptions> versionStrings)
        {
            this.userManager = userManager;
            this.jwtFactory = jwtFactory;
            this.jwtOptions = jwtOptions.Value;
            this.versionStrings = versionStrings;

            serializerSettings = new JsonSerializerSettings
            {
                Formatting = Formatting.Indented
            };
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Post([FromBody]CredentialsViewModel credentials)
        {
            if (!ModelState.IsValid)
            {
                return new BadRequestObjectResult(ModelState);
            }

            var identity = await GetClaimsIdentity(credentials.UserName, credentials.Password);
            if (identity == null)
            {
                return new BadRequestObjectResult(Errors.AddErrorToModelState("login_failure", "Invalid username or password.", ModelState));
            }

            // Serialize and return the response
            var response = new
            {
                id = identity.Claims.Single(c => c.Type == "id").Value,
                auth_token = await jwtFactory.GenerateEncodedToken(credentials.UserName, identity),
                expires_in = (int)jwtOptions.ValidFor.TotalSeconds
            };

            return new OkObjectResult(response);
        }

        [HttpGet("version")]
        public IActionResult Version()
        {
            return new OkObjectResult(new
            {
                Git = versionStrings.Value.GitRevision,
                Build = versionStrings.Value.BuildNumber
            });
        }

        private async Task<ClaimsIdentity> GetClaimsIdentity(string userName, string password)
        {
            if (!string.IsNullOrEmpty(userName) && !string.IsNullOrEmpty(password))
            {
                // get the user to verifty
                var userToVerify = await userManager.FindByNameAsync(userName);

                if ((userToVerify != null) && (await userManager.CheckPasswordAsync(userToVerify, password)))
                {
                    return await Task.FromResult(jwtFactory.GenerateClaimsIdentity(userName, userToVerify.Id));
                }
            }

            // Credentials are invalid, or account doesn't exist
            return await Task.FromResult<ClaimsIdentity>(null);
        }
    }
}