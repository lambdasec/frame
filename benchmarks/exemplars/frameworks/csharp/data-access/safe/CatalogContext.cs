using Microsoft.EntityFrameworkCore;

namespace Catalog
{
    // The EF Core context the controller is handed (registered with AddDbContext).
    public class CatalogContext : DbContext
    {
        public CatalogContext(DbContextOptions<CatalogContext> options) : base(options) { }

        public DbSet<Product> Products { get; set; }
    }
}
