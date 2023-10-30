using System;
namespace JWTAuth.Models.DTO
{
	public class Status
	{
        public byte StatusCode { get; set; }
        public string? Message { get; set; }
		public string? Token { get; set; }	
	}
}

