using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using ExtendEFIdentity.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace ExtendEFIdentity
{
    public class AppDbContext : IdentityDbContext<AppUser>
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            builder.Entity<AppUser>(o =>
            {
                o.Property(c => c.FullName)
                    .HasMaxLength(255)
                    .IsUnicode(false);

                o.HasIndex(c => c.FullName)
                    .HasName("IDX_Users_FullName")
                    .IsUnique(false);
            });
        }
    }
}
