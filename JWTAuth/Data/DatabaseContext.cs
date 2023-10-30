using System;
using JWTAuth.Models.Domain;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JWTAuth.Data
{
	public class DatabaseContext : IdentityDbContext<ApplicationUser>
	{ 
		public DatabaseContext(DbContextOptions<DatabaseContext> options) : base(options)
		{

		}
        public DbSet<TokenInfo> TokenInfo { get; set; }
    }
}

