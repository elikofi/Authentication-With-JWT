using System;
namespace JWTAuth.Models.DTO
{
	public class TokenResponse
	{
        public string? TokenString { get; set; }
        public DateTime ValidTo { get; set; }
        public bool IsSuccessful { get; set; }
        public string Message { get; set; }
    }
}

