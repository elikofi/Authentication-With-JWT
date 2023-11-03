using System;
using JWTAuth.Models.Domain;
using JWTAuth.Models.DTO;
using JWTAuth.Roles;
using Microsoft.AspNetCore.Identity;

namespace JWTAuth.Repositories.Abstract
{
	public interface IAuthService
	{
        Task<Status> SeedRolesAsync();
        Task<Status> RegisterAsync(Registration model);
        Task<TokenResponse> LoginAsync(Login model);
        Task<Status> MakeAdminAsync(UpdatePermissions model);
        Task<Status> MakeSuperAdminAsync(UpdatePermissions model);
        Task<Status> ChangePasswordAsync(ChangePassword model);
        Task<Status> LogoutAsync();
        Task<IEnumerable<ApplicationUser>> GetAppUsersAsync();
        Task<Status> DeleteUserAsync(string id);


        Task<object?> GetUserRoles(string email);
    }
}

