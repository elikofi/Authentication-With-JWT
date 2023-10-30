using System;
using System.Security.Claims;
using JWTAuth.Data;
using JWTAuth.Models.Domain;
using JWTAuth.Models.DTO;
using JWTAuth.Repositories.Abstract;
using JWTAuth.Roles;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace JWTAuth.Repositories.Implementation
{
	public class AuthService : IAuthService
	{
        private readonly UserManager<ApplicationUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IConfiguration configuration;
        private readonly ITokenService tokenService;
        private readonly DatabaseContext context;
        
        public AuthService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration,ITokenService tokenService, DatabaseContext context)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            this.configuration = configuration;
            this.tokenService = tokenService;
            this.context = context;
        }


        readonly Status status = new();

        public async Task<Status> LoginAsync(Login model)
        {
            try
            {
                var user = await userManager.FindByNameAsync(model.UserName);
                if (user == null)
                {
                    status.StatusCode = 0;
                    status.Message = "Invalid Username.";
                    return status;
                }

                var isPasswordCorrect = await userManager.CheckPasswordAsync(user, model.Password);

                if (!isPasswordCorrect)
                {
                    status.StatusCode = 0;
                    status.Message = "Invalid Password.";
                    return status;
                }

                var userRoles = await userManager.GetRolesAsync(user);

                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(ClaimTypes.NameIdentifier, user.Id),
                    new Claim("JWTID", Guid.NewGuid().ToString()),
                    new Claim("FirstName", user.FirstName),
                    new Claim("LastName", user.LastName),
                };
                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }

                var token = tokenService.GetToken(authClaims);
                //var refreshToken = tokenService.GetRefreshToken();
                //var tokenInfo = context.TokenInfo.FirstOrDefault(a => a.UserName == user.UserName);

                //if (tokenInfo == null)
                //{
                //    var info = new TokenInfo
                //    {
                //        UserName = user.UserName,
                //        RefreshToken = refreshToken,
                //        RefreshTokenExpiry = DateTime.Now.AddHours(1)
                //    };
                //    context.TokenInfo.Add(info);
                //}
                //else
                //{
                //    tokenInfo.RefreshToken = refreshToken;
                //    tokenInfo.RefreshTokenExpiry = DateTime.Now.AddHours(1);
                //}
                //var validationErrors = context.GetValidationErrors();

                await context.SaveChangesAsync();

                status.StatusCode = 1;
                status.Token = token;
                status.Message = "Login Successful.";
                return status;
            }
            catch (DbUpdateException e)
            {
                status.StatusCode = 0;
                status.Message = "Error Occured, unable to login.";
                status.Message = e.Message;
                return status;

            }

        }

        public async Task<Status> MakeAdminAsync(UpdatePermissions model)
        {
            try
            {
                var user = await userManager.FindByNameAsync(model.UserName);

                if (user == null)
                {
                    status.StatusCode = 0;
                    status.Message = "Invalid Username.";
                    return status;
                }

                await userManager.AddToRoleAsync(user, UserRoles.ADMIN);

                status.StatusCode = 1;
                status.Message = user.UserName + " is now an admin.";
                return status;
            }
            catch (Exception e)
            {
                status.StatusCode = 0;
                status.Message = e.Message;
                return status;
            }

        }

        public Task<Status> MakeSuperAdminAsync(UpdatePermissions model)
        {
            throw new NotImplementedException();
        }


        //Registering user.
        public async Task<Status> RegisterAsync(Registration model)
        {
            var isExistsUser = await userManager.FindByNameAsync(model.UserName);

            if (isExistsUser != null)
            {
                status.StatusCode = 0;
                status.Message = "User already exists.";
                return status;
            }


            ApplicationUser newUser = new ApplicationUser()
            {
                FirstName = model.FirstName,
                LastName = model.LastName,
                Email = model.Email,
                UserName = model.UserName,
                SecurityStamp = Guid.NewGuid().ToString(),
            };

            var createUserResult = await userManager.CreateAsync(newUser, model.Password);

            if (!createUserResult.Succeeded)
            {
                var errorString = "User Creation Failed Beacause: ";
                foreach (var error in createUserResult.Errors)
                {
                    errorString += " # " + error.Description;
                }
                status.StatusCode = 0;
                status.Message = errorString;
                return status;
            }

            // Admin Role to all users
            //await userManager.AddToRoleAsync(newUser, UserRoles.SUPERADMIN);

            //Default user role
            await userManager.AddToRoleAsync(newUser, UserRoles.USER);
            status.StatusCode = 1;
            status.Message = "User created successfully.";
            return status;

        }

        public async Task<Status> SeedRolesAsync()
        {
            bool isOwnerRoleExists = await roleManager.RoleExistsAsync(UserRoles.SUPERADMIN);
            bool isAdminRoleExists = await roleManager.RoleExistsAsync(UserRoles.ADMIN);
            bool isUserRoleExists = await roleManager.RoleExistsAsync(UserRoles.USER);

            if (isOwnerRoleExists && isAdminRoleExists && isUserRoleExists)
            {
                status.StatusCode = 0;
                status.Message = "Role seeding already done.";
                return status;
            }
                

            await roleManager.CreateAsync(new IdentityRole(UserRoles.SUPERADMIN));
            await roleManager.CreateAsync(new IdentityRole(UserRoles.ADMIN));
            await roleManager.CreateAsync(new IdentityRole(UserRoles.USER));

            status.StatusCode = 1;
            status.Message = "Role seeding done successfully.";
            return status;
        }
    }
}

