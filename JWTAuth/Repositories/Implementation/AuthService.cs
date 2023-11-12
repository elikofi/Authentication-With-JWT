using System;
using System.Security.Claims;
using JWTAuth.Data;
using JWTAuth.Models.Domain;
using JWTAuth.Models.DTO;
using JWTAuth.Repositories.Abstract;
using JWTAuth.Roles;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.EntityFrameworkCore;
using Microsoft.VisualBasic;
using Newtonsoft.Json.Linq;
using System.Threading;

namespace JWTAuth.Repositories.Implementation
{
	public class AuthService : IAuthService
	{
        private readonly UserManager<ApplicationUser> userManager;
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IConfiguration configuration;
        private readonly ITokenService tokenService;
        private readonly DatabaseContext context;
        

        public AuthService(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, RoleManager<IdentityRole> roleManager,
            IConfiguration configuration, ITokenService tokenService, DatabaseContext context)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.roleManager = roleManager;
            this.configuration = configuration;
            this.tokenService = tokenService;
            this.context = context;
        } 


        readonly Status status = new();
        readonly DateTime registrationDate = DateTime.UtcNow;

        

        public async Task<LoginResponse> LoginAsync(Login model)
        {
            try
            {
                var user = await userManager.FindByNameAsync(model.UserName);


                var signIn = await signInManager.PasswordSignInAsync(user, model.Password, false, true);
                if (signIn.Succeeded)
                {
                    if (user != null && await userManager.CheckPasswordAsync(user, model.Password))
                    {
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
                        #region
                        var refreshToken = tokenService.GetRefreshToken();
                        var tokenInfo = context.TokenInfo.FirstOrDefault(a => a.UserName == user.UserName);
                        if (tokenInfo == null)
                        {
                            var info = new TokenInfo
                            {
                                UserName = user.UserName,
                                RefreshToken = refreshToken,
                                RefreshTokenExpiry = DateTime.UtcNow.AddDays(1)
                            };
                            context.TokenInfo.Add(info);
                        }

                        else
                        {
                            tokenInfo.RefreshToken = refreshToken;
                            tokenInfo.RefreshTokenExpiry = DateTime.UtcNow.AddDays(1);
                        }

                        #endregion

                        await context.SaveChangesAsync();

                        return new LoginResponse
                        {
                            UserName = user.UserName,
                            Token = token.TokenString,
                            RefreshToken = refreshToken,
                            Expiration = token.ValidTo,
                            StatusCode = 1,
                            Message = "Logged in"
                        };
                    }

                }
                else if (signIn.IsLockedOut)
                {
                    return new LoginResponse
                    {
                        UserName = user.UserName,
                        StatusCode = 0,
                        Message = "User has logged out."
                    };
                }
                return new LoginResponse
                {
                    UserName = user.UserName,
                    StatusCode = 0,
                    Message = "Login unsuccessful."
                };

            }
            catch (DbUpdateException e)
            {
                return new LoginResponse
                {

                    StatusCode = 0,
                    Message = e.Message
                };
            }

        }

        //MAKE ADMIN
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


        //MAKE SUPER ADMIN
        public async Task<Status> MakeSuperAdminAsync(UpdatePermissions model)
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
                await userManager.AddToRoleAsync(user, UserRoles.SUPERADMIN);

                status.StatusCode = 1;
                status.Message = user.UserName + " is now a super admin.";
                return status;
            }
            catch (Exception e)
            {
                status.StatusCode = 0;
                status.Message = e.Message;
                return status;
            }
        }


        //REGISTER USER
        public async Task<Status> RegisterAsync(Registration model)
        {
            try
            {
                var isExistsUser = await userManager.FindByNameAsync(model.UserName);

                if (isExistsUser != null)
                {
                    status.StatusCode = 0;
                    status.Message = "Username already exists. Choose a different username.";
                    return status;
                }


                ApplicationUser newUser = new()
                {
                    FirstName = model.FirstName,
                    LastName = model.LastName,
                    Email = model.Email,
                    UserName = model.UserName,
                    SecurityStamp = Guid.NewGuid().ToString(),
                    EmailConfirmed = false, //added this line
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
                //#region trying to confirm email
                //var emailConfirmToken = await userManager.GenerateEmailConfirmationTokenAsync(newUser);//added this line

                //var emailBody = $"Please confirm you email address <a href=\"#URL\">Click here</a>";
                ////https://localhost:7209/authentication/verifyemail/userid=sdas&code=dasdasd
                //var callback_url = "://" + Request.Host +

                //#endregion
                // TO MAKE USER ADMIN
                //await userManager.AddToRoleAsync(newUser, UserRoles.SUPERADMIN);

                //Default user role
                await userManager.AddToRoleAsync(newUser, UserRoles.USER);
                status.StatusCode = 1;
                status.Message = "User created successfully.";
                return status;
            }
            catch (Exception e)
            {
                status.StatusCode = 0;
                status.Message = e.Message;
                return status;
            }

        }
        //SEED ROLES TO DB
        public async Task<Status> SeedRolesAsync()
        {
            try
            {
                bool isOwnerRoleExists = await roleManager.RoleExistsAsync(UserRoles.SUPERADMIN);
                bool isAdminRoleExists = await roleManager.RoleExistsAsync(UserRoles.ADMIN);
                bool isUserRoleExists = await roleManager.RoleExistsAsync(UserRoles.USER);
                bool isSuperUserRoleExists = await roleManager.RoleExistsAsync(UserRoles.SUPERUSER);

                if (isOwnerRoleExists && isAdminRoleExists && isUserRoleExists && isSuperUserRoleExists)
                {
                    status.StatusCode = 0;
                    status.Message = "Role seeding already done.";
                    return status;
                }


                await roleManager.CreateAsync(new IdentityRole(UserRoles.SUPERADMIN));
                await roleManager.CreateAsync(new IdentityRole(UserRoles.ADMIN));
                await roleManager.CreateAsync(new IdentityRole(UserRoles.USER));
                await roleManager.CreateAsync(new IdentityRole(UserRoles.SUPERUSER));

                status.StatusCode = 1;
                status.Message = "Role seeding done successfully.";
                return status;
            }
            catch (Exception e)
            {
                status.StatusCode = 0;
                status.Message = e.Message;
                return status;
            }
        }


        //CHANGE PASSWORD
        public async Task<Status> ChangePasswordAsync(ChangePassword model)
        {
            try
            {
                //find the user.

                var user = await userManager.FindByNameAsync(model.Username);
                if (user == null)
                {
                    status.StatusCode = 0;
                    status.Message = "Username not found.";
                    return status;
                }
                //check the current password.
                if (!await userManager.CheckPasswordAsync(user, model.CurrentPassword))
                {
                    status.StatusCode = 0;
                    status.Message = "Current password is wrong.";
                    return status;
                }
                //create new password
                var newPassword = await userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);

                if (!newPassword.Succeeded)
                {
                    status.StatusCode = 0;
                    status.Message = "Password changing failed.";
                    return status;
                }
                status.StatusCode = 1;
                status.Message = "Changed password.";
                return status;
            }
            catch (Exception e)
            {
                status.StatusCode = 0;
                status.Message = e.Message;
                return status;
            }
            
        }

        public async Task<Status> LogoutAsync()
        {
            await signInManager.SignOutAsync();
            status.StatusCode = 1;
            status.Message = "Signed out.";
            return status;
        }
        
        //GET ALL USERS
        public async Task<IEnumerable<ApplicationUser>> GetAppUsersAsync()
        {
            var users = await context.Users.AsNoTracking().ToListAsync();
            if (users != null)
            {
                status.StatusCode = 1;
                return users;
            }

            
            return null;
        }

        //DELETE USER
        public async Task<Status> DeleteUserAsync(string id)
        {
            var user =await context.Users.FindAsync(id);
            context.Users.Remove(user);
            await context.SaveChangesAsync();
            status.StatusCode = 1;
            status.Message = "Deleted Successfully.";
            return status;
        }



        //GET THE ROLE OF A USER.
        public async Task<object?> GetUserRoles(string email)
        {
            try
            {
                var user = await userManager.FindByEmailAsync(email);

                if (user == null)
                {

                    return "No user with this email.";
                }

                var roles = await userManager.GetRolesAsync(user);

                return roles;
            }
            catch (Exception)
            {
                return "Error occured, unable to get the role of user.";
            }
        }

        
        
        public async Task<Status> MakeSuperUserAsync(UpdatePermissions model)
        {

           

            DateTime registrationEndDate = registrationDate.AddSeconds(50);

            var user = await userManager.FindByNameAsync(model.UserName);

            if (user != null && registrationDate < registrationEndDate)
            {
                await userManager.AddToRoleAsync(user, UserRoles.SUPERUSER);

                status.StatusCode = 1;
                status.Message = user.UserName + " is now a super user.";
                return status;
            }
            await userManager.AddToRoleAsync(user, UserRoles.USER);



            status.StatusCode = 0;
            status.Message = "Invalid Username.";
            return status;


        }



        //public async Task<TokenResponse> LoginAsync(Login model)
        //{
        //    try
        //    {
        //        TokenResponse tokenResponse = new();
        //        var user = await userManager.FindByNameAsync(model.UserName);
        //        if (user == null)
        //        {
        //            tokenResponse.TokenString = null;
        //            tokenResponse.ValidTo = DateTime.Now;
        //            tokenResponse.IsSuccessful = false;
        //            tokenResponse.Message = "Username is incorrect.";
        //            return tokenResponse;
        //        }

        //        var isPasswordCorrect = await userManager.CheckPasswordAsync(user, model.Password);

        //        if (!isPasswordCorrect)
        //        {
        //            tokenResponse.TokenString = null;
        //            tokenResponse.ValidTo = DateTime.Now;
        //            tokenResponse.IsSuccessful = false;
        //            tokenResponse.Message = "Password is incorrect.";
        //            return tokenResponse;
        //        }

        //        var signIn = await signInManager.PasswordSignInAsync(user, model.Password, false, true);
        //        if (signIn.Succeeded)
        //        {
        //            var userRoles = await userManager.GetRolesAsync(user);

        //            var authClaims = new List<Claim>
        //            {
        //                new Claim(ClaimTypes.Name, user.UserName),
        //                new Claim(ClaimTypes.NameIdentifier, user.Id),
        //                new Claim("JWTID", Guid.NewGuid().ToString()),
        //                new Claim("FirstName", user.FirstName),
        //                new Claim("LastName", user.LastName),
        //            };
        //            foreach (var userRole in userRoles)
        //            {
        //                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
        //            }

        //            var token = tokenService.GetToken(authClaims);

        //            await context.SaveChangesAsync();

        //            return token;
        //        }
        //        else if (signIn.IsLockedOut)
        //        {
        //            tokenResponse.TokenString = null;
        //            tokenResponse.ValidTo = DateTime.Now;
        //            tokenResponse.IsSuccessful = false;
        //            tokenResponse.Message = "User logged out.";
        //            return tokenResponse;
        //        }
        //        else
        //        {
        //            tokenResponse.TokenString = null;
        //            tokenResponse.ValidTo = DateTime.Now;
        //            tokenResponse.IsSuccessful = false;
        //            tokenResponse.Message = "Login unsuccessful";
        //            return tokenResponse;
        //        }


        //    }
        //    catch (DbUpdateException e)
        //    {
        //        TokenResponse tokenResponse = new()
        //        {
        //            TokenString = null,
        //            ValidTo = DateTime.Now,
        //            IsSuccessful = false,
        //            Message = e.Message
        //        };
        //        return tokenResponse;

        //    }

        //}


        //private class RegistrationDate
        //{
        //    DateTime registrationDate = DateTime.UtcNow;
        //}
    }
   
}

