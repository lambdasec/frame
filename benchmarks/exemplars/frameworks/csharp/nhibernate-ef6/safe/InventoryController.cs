using System.Collections.Generic;
using System.Data.Entity;
using System.Data.SqlClient;
using System.Linq;
using System.Web.Mvc;
using NHibernate;

namespace Warehouse.Controllers
{
    public class InventoryController : Controller
    {
        private readonly ISession _session;
        private readonly WarehouseDb _db = new WarehouseDb();

        public InventoryController(ISession session)
        {
            _session = session;
        }

        public ActionResult Search(string sku)
        {
            var items = _session.CreateSQLQuery("SELECT * FROM Items WHERE Sku = :sku").SetParameter("sku", sku).List();
            return View(items);
        }

        public ActionResult ByOwner(string owner)
        {
            var items = _session.CreateQuery("from Item i where i.Owner = :owner").SetParameter("owner", owner).List<Item>();
            return View(items);
        }

        public ActionResult Find(string name)
        {
            var items = _db.Database.SqlQuery<Item>("SELECT * FROM Items WHERE Name = @p0", name).ToList();
            return View(items);
        }

        public ActionResult Clear(string bin)
        {
            _db.Database.ExecuteSqlCommand("DELETE FROM Items WHERE Bin = @p0", new SqlParameter("@p0", bin));
            return RedirectToAction("Index");
        }
    }
}
