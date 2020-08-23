using Microsoft.EntityFrameworkCore;
using BasicCustomIdentity.Entities;
using System.Diagnostics.CodeAnalysis;

namespace BasicCustomIdentity
{
    public class BasicIdentityDbContext : DbContext
    {
        public BasicIdentityDbContext([NotNullAttribute] DbContextOptions<BasicIdentityDbContext> options) : base(options)
        {
        }
        public virtual DbSet<BasicUser> BasicUsers { get; set; }
    }
}
