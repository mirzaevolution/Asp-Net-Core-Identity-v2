using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.EntityFrameworkCore.SqlServer;

namespace BasicCustomIdentity.Entities
{
    public class BasicUser
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string FullName { get; set; }
        public string UserName { get; set; }
        public string NormalizedUserName { get; set; }
        public string PasswordHash { get; set; }
    }

    public class BasicUserEntityTypeConfiguration : IEntityTypeConfiguration<BasicUser>
    {
        public void Configure(EntityTypeBuilder<BasicUser> builder)
        {
            builder.ToTable("BasicUsers");
            builder.HasKey(c => c.Id);
            builder.Property(c => c.FullName)
                .IsRequired()
                .HasMaxLength(255)
                .IsUnicode(false);
            builder.Property(c => c.UserName)
                .IsRequired()
                .HasMaxLength(255)
                .IsUnicode(false);
            builder.Property(c => c.NormalizedUserName)
                .IsRequired()
                .HasMaxLength(255)
                .IsUnicode(false);
            builder.Property(c => c.PasswordHash)
                .IsRequired()
                .HasMaxLength(255)
                .IsUnicode(false);

            builder.HasIndex(c => c.FullName)
                .IsUnique(false)
                .HasName("IDX_BasicUsers_FullName");

            builder.HasIndex(c => c.UserName)
                .IsUnique(false)
                .HasName("IDX_BasicUsers_UserName");

            builder.HasIndex(c => c.NormalizedUserName)
                .IsUnique(false)
                .HasName("IDX_BasicUsers_NormalizedUserName");
            builder.HasIndex(c => c.PasswordHash)
                .IsUnique(false)
                .HasName("IDX_BasicUsers_PasswordHashPasswordHash");
        }
    }
}
