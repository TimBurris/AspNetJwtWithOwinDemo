using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace WebApplication1.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        [AllowAnonymous]
        public ActionResult Login()
        {
            return View();
        }

        [AllowAnonymous]
        [HttpPost]
        public ActionResult Authenticate(string username, string password)
        {
            //validate credentials

            //generate jwt
            var key = Startup.GetSymmetricSecurityKey();
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims=new List<System.Security.Claims.Claim>();
            claims.Add(new System.Security.Claims.Claim(type: System.Security.Claims.ClaimTypes.Sid, value: "8675309"));
            claims.Add(new System.Security.Claims.Claim(type: System.Security.Claims.ClaimTypes.Name, value: "Jenny, Jenny"));
            claims.Add(new System.Security.Claims.Claim(type: System.Security.Claims.ClaimTypes.Role, value: "Admin"));
            claims.Add(new System.Security.Claims.Claim(type: System.Security.Claims.ClaimTypes.Role, value: "PowerUser"));
            claims.Add(new System.Security.Claims.Claim(type: "CustomClaim", value: "custom value"));

            var jwtToken = new JwtSecurityToken(
                issuer: Startup.GetIssuer(),
                audience: Startup.GetAudience(),
                expires: DateTime.Now.AddMinutes(60),
                claims: claims,
                signingCredentials: credentials
            );

            string token= new JwtSecurityTokenHandler().WriteToken(jwtToken);

            return Json(new { token = token });
        }

        [HttpGet]
        [Authorize(Roles ="Admin")]
        public ActionResult GetSomeData()
        {

            var result = new SomeData()
            {
                Data=DateTime.Now.Ticks.ToString(),
                Name=User.Identity.Name,
                UserId=System.Security.Claims.ClaimsPrincipal.Current.Claims.FirstOrDefault(x=>x.Type== System.Security.Claims.ClaimTypes.Sid)?.Value
            };

            return Json(result, JsonRequestBehavior.AllowGet);
        }
    }

    public class SomeData
    {
        public string Data { get; set; }
        public string UserId { get; set; }
        public string Name { get; set; }

    }
}
