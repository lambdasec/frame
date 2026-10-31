using System.Data.Entity;

namespace Warehouse
{
    // The EF6 context (System.Data.Entity) the controller creates.
    public class WarehouseDb : DbContext
    {
        public DbSet<Item> Items { get; set; }
    }
}
