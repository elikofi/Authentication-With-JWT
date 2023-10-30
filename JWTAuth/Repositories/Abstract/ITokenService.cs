using System;
using JWTAuth.Models.DTO;
using System.Security.Claims;

namespace JWTAuth.Repositories.Abstract
{
	public interface ITokenService
	{
        string GetToken(List<Claim> claim);
        string GetRefreshToken();
        ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
    }
}

