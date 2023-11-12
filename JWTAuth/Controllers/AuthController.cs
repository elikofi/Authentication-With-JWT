using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using JWTAuth.Models.Domain;
using JWTAuth.Models.DTO;
using JWTAuth.Repositories.Abstract;
using JWTAuth.Repositories.Implementation;
using JWTAuth.Roles;
using Microsoft.AspNetCore.Authorization;
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
        [Authorize(Roles = "SUPERADMIN")]
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
            //if (result.StatusCode == 1)
            //    return Ok(result);

            //return Unauthorized();

            if (result.StatusCode == 1)
            {
                return Ok(result);
            }
            return Unauthorized();
        }

        //make super admin
        
        [HttpPost]
        [Route("Make-SuperAdmin")]
        [Authorize(Roles = "SUPERADMIN")]
        public async Task<IActionResult> MakeSuperAdmin([FromBody] UpdatePermissions model)
        {
            var result = await service.MakeSuperAdminAsync(model);
            if (result.StatusCode == 0)
            {
                return BadRequest();
            }
            return Ok(result);
        }

        //make admin
        [HttpPost]
        [Route("Make-Admin")]
        [Authorize(Roles = "SUPERADMIN")]
        public async Task<IActionResult> MakeAdmin([FromBody] UpdatePermissions model)
        {
            var result = await service.MakeAdminAsync(model);
            if (result.StatusCode == 0)
            {
                return BadRequest();
            }
            return Ok(result);
        }

        //Change password
        [HttpPost]
        [Route("Changepassword")]
        [Authorize]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePassword model)
        {
            var result = await service.ChangePasswordAsync(model);

            if (result.StatusCode == 0)
            {
                return BadRequest();
            }
            return Ok(result);
        }

        //Sign out
        [Authorize]
        [HttpPost]
        [Route("Logout")]
        public async Task<IActionResult> Logout()
        {
            await service.LogoutAsync();
            return Ok("Signed Out!");
        }

        //Get all users
        [HttpGet]
        [Route("GetAppUsers")]
        [Authorize(Roles = "SUPERADMIN, ADMIN, SUPERUSER")]
        public async Task<IActionResult> GetAppUsers()
        {
            var data = await service.GetAppUsersAsync();
            if(data != null)
                return Ok(data);
            return BadRequest();
        }

        [HttpDelete]
        [Route("DeleteUser")]
        [Authorize(Roles = "SUPERADMIN")]
        public async Task<IActionResult> DeleteUser(string id)
        {
            var product = await service.DeleteUserAsync(id);
            if (product.StatusCode == 1)
            {
                return Ok();
            }
            return BadRequest();
        }

        [HttpGet]
        [Route("GetUserRole")]
        [Authorize(Roles = "SUPERADMIN, ADMIN")]
        public async Task<IActionResult> GetUserRole(string email)
        {
            var userRole = await service.GetUserRoles(email);
            return Ok(userRole);
        }

        //make super user

        [HttpPost]
        [Route("Make-SuperUser")]
        [Authorize(Roles = "SUPERADMIN")]
        public async Task<IActionResult> MakeSuperUser([FromBody] UpdatePermissions model)
        {
            var result = await service.MakeSuperUserAsync(model);
            if (result.StatusCode == 0)
            {
                return BadRequest();
            }
            return Ok(result);
        }
    }
}

