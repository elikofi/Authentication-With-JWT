using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using JWTAuth.Models.Domain;
using JWTAuth.Models.DTO;
using JWTAuth.Repositories.Abstract;
using JWTAuth.Repositories.Implementation;
using JWTAuth.Roles;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

// For more information on enabling MVC for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace JWTAuth.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService service;
        private readonly ITokenService tokenService;

        public AuthController(IAuthService service, ITokenService tokenService)
        {
            this.service = service;
            this.tokenService = tokenService;
        }


        // Route For Seeding my roles to DB
        [HttpPost]
        [Route("seed-roles")]
        public async Task<IActionResult> SeedRoles()
        {
            var seerRoles = await service.SeedRolesAsync();

            return Ok(seerRoles);
        }

        //Registering user.
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] Registration model)
        {
            var result = await service.RegisterAsync(model);
            if (result.StatusCode == 1)
                return Ok(result);

            return Unauthorized();
        }

        //Login method
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] Login model)
        {
            var result = await service.LoginAsync(model);
            if (result.StatusCode == 1)
                return Ok(result);

            return Unauthorized();
        }

    }
}

