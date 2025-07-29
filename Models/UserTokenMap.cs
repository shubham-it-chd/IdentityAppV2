using System.Text.Json;

namespace IdentityAppV2.Models;

public class UserTokenMap
{
    public int Id { get; set; }
    public string UserId { get; set; } = string.Empty;
    public int ApplicationId { get; set; }
    public string AccessToken { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public string Claims { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAt { get; set; }
    public bool IsRevoked { get; set; } = false;
    public DateTime? RevokedAt { get; set; }

    // Navigation properties
    public ApplicationUser User { get; set; } = null!;
    public Application Application { get; set; } = null!;

    // Helper methods for claims
    public Dictionary<string, object> GetClaimsDictionary()
    {
        return JsonSerializer.Deserialize<Dictionary<string, object>>(Claims) ?? new Dictionary<string, object>();
    }

    public void SetClaimsDictionary(Dictionary<string, object> claims)
    {
        Claims = JsonSerializer.Serialize(claims);
    }
} 