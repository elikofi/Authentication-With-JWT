using System;
using System.ComponentModel.DataAnnotations;

namespace JWTAuth.Models.DTO
{
	public class UpdatePermissions
	{
        [Required(ErrorMessage = "UserName is required")]
        public string? UserName { get; set; }
    }
}

