using Microsoft.EntityFrameworkCore;

namespace Velusia.ClientOfAnother.Models;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions options)
        : base(options)
    {
    }
}
