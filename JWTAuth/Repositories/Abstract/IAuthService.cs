using System;
using JWTAuth.Models.DTO;

namespace JWTAuth.Repositories.Abstract
{
	public interface IAuthService
	{
        Task<Status> SeedRolesAsync();
        Task<Status> RegisterAsync(Registration model);
        Task<Status> LoginAsync(Login model);
        Task<Status> MakeAdminAsync(UpdatePermissions model);
        Task<Status> MakeSuperAdminAsync(UpdatePermissions model);
    }
}

