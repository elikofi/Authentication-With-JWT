using System;
namespace JWTAuth.Models.DTO
{
	public class LoginResponse
	{
        public string? Token { get; set; }
        public string? RefreshToken { get; set; }
        public DateTime? Expiration { get; set; }
        public string? Username { get; set; }
    }
}

