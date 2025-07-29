using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using IdentityAppV2.Models;

namespace IdentityAppV2.Data;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public DbSet<Application> Applications { get; set; }
    public DbSet<UserTokenMap> UserTokenMaps { get; set; }
    public DbSet<UserClaim> UserClaims { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Configure OpenIddict entities
        builder.UseOpenIddict();

        // Configure Application entity
        builder.Entity<Application>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Name).IsRequired().HasMaxLength(200);
            entity.Property(e => e.ClientId).IsRequired().HasMaxLength(200);
            entity.Property(e => e.ClientSecret).IsRequired().HasMaxLength(500);
            entity.Property(e => e.RedirectUris).HasMaxLength(2000);
            entity.Property(e => e.PostLogoutRedirectUris).HasMaxLength(2000);
            entity.Property(e => e.Permissions).HasMaxLength(2000);
            entity.Property(e => e.CreatedAt).IsRequired();
            entity.Property(e => e.IsActive).IsRequired().HasDefaultValue(true);
            
            // Configure unique constraint for ClientId
            entity.HasIndex(e => e.ClientId).IsUnique();
        });

        // Configure UserTokenMap entity
        builder.Entity<UserTokenMap>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.UserId).IsRequired().HasMaxLength(450);
            entity.Property(e => e.ApplicationId).IsRequired();
            entity.Property(e => e.AccessToken).IsRequired();
            entity.Property(e => e.RefreshToken).IsRequired();
            entity.Property(e => e.Claims).IsRequired();
            entity.Property(e => e.CreatedAt).IsRequired();
            entity.Property(e => e.ExpiresAt).IsRequired();
            
            // Configure relationships
            entity.HasOne(e => e.User)
                  .WithMany()
                  .HasForeignKey(e => e.UserId)
                  .OnDelete(DeleteBehavior.Cascade);
                  
            entity.HasOne(e => e.Application)
                  .WithMany()
                  .HasForeignKey(e => e.ApplicationId)
                  .OnDelete(DeleteBehavior.Cascade);
            
            entity.HasIndex(e => new { e.UserId, e.ApplicationId }).IsUnique();
            entity.HasIndex(e => e.RefreshToken).IsUnique();
        });

        // Configure UserClaim entity (custom table to avoid conflict with Identity UserClaims)
        builder.Entity<UserClaim>(entity =>
        {
            entity.ToTable("CustomUserClaims"); // Use different table name to avoid conflict
            entity.HasKey(e => e.Id);
            entity.Property(e => e.UserId).IsRequired().HasMaxLength(450);
            entity.Property(e => e.ClaimType).IsRequired().HasMaxLength(200);
            entity.Property(e => e.ClaimValue).IsRequired().HasMaxLength(2000);
            entity.Property(e => e.Issuer).HasMaxLength(200);
            entity.Property(e => e.CreatedAt).IsRequired();
            
            // Configure relationship
            entity.HasOne(e => e.User)
                  .WithMany()
                  .HasForeignKey(e => e.UserId)
                  .OnDelete(DeleteBehavior.Cascade);
            
            // Configure index for performance
            entity.HasIndex(e => new { e.UserId, e.ClaimType });
        });

        // Configure ApplicationUser
        builder.Entity<ApplicationUser>(entity =>
        {
            entity.Property(e => e.FirstName).HasMaxLength(100);
            entity.Property(e => e.LastName).HasMaxLength(100);
            entity.Property(e => e.ExternalId).HasMaxLength(200);
            entity.Property(e => e.ExternalProvider).HasMaxLength(50);
            entity.Property(e => e.CreatedAt).IsRequired();
            entity.Property(e => e.IsActive).IsRequired().HasDefaultValue(true);
            
            // Configure index for external authentication
            entity.HasIndex(e => new { e.ExternalId, e.ExternalProvider }).IsUnique()
                  .HasFilter("[ExternalId] IS NOT NULL AND [ExternalProvider] IS NOT NULL");
        });
    }
} 