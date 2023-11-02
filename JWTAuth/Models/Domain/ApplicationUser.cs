using System;
using JWTAuth.Roles;
using Microsoft.AspNetCore.Identity;

namespace JWTAuth.Models.Domain
{
	public class ApplicationUser : IdentityUser
	{
		public string? FirstName { get; set; }
		public string? LastName { get; set; }
	}
}

