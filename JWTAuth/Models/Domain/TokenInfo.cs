using System;
namespace JWTAuth.Models.Domain
{
	public class TokenInfo
	{
        public int Id { get; set; }
        public string UserName { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
        public DateTime RefreshTokenExpiry { get; set; } 
    }
}

