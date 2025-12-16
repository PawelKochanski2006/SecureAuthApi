using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SecureAuthApi.Models;

namespace SecureAuthApi.Data;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<LdapConfiguration> LdapConfigurations => Set<LdapConfiguration>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<ApplicationUser>(entity =>
        {
            entity.Property(e => e.DisplayName).HasMaxLength(256);
            entity.Property(e => e.FirstName).HasMaxLength(128);
            entity.Property(e => e.LastName).HasMaxLength(128);
        });

        builder.Entity<RefreshToken>(entity =>
        {
            entity.HasIndex(e => e.Token).IsUnique();
            entity.HasIndex(e => e.ExpiresAt);
            entity.HasIndex(e => new { e.UserId, e.IsRevoked });
            
            entity.HasOne(e => e.User)
                .WithMany(u => u.RefreshTokens)
                .HasForeignKey(e => e.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<LdapConfiguration>(entity =>
        {
            entity.Property(e => e.ServerUrl).HasMaxLength(512).IsRequired();
            entity.Property(e => e.BaseDn).HasMaxLength(512).IsRequired();
            entity.Property(e => e.BindDn).HasMaxLength(512).IsRequired();
            entity.Property(e => e.EncryptedBindPassword).IsRequired();
            entity.Property(e => e.SearchFilter).HasMaxLength(512).IsRequired();
        });
    }
}
