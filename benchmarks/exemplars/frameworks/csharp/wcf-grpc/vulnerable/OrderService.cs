using System.Data.SqlClient;
using System.Diagnostics;
using System.ServiceModel;

namespace Billing.Wcf
{
    [ServiceContract]
    public interface IOrderService
    {
        [OperationContract]
        string Lookup(string customer);

        [OperationContract]
        void Archive(string ledger);
    }

    [ServiceBehavior(InstanceContextMode = InstanceContextMode.PerCall)]
    public class OrderService : IOrderService
    {
        private const string Connection = "Server=.;Database=Billing;Integrated Security=true";

        public string Lookup(string customer)
        {
            using (var conn = new SqlConnection(Connection))
            {
                conn.Open();
                var cmd = new SqlCommand("SELECT Total FROM Orders WHERE Customer = '" + customer + "'", conn); // frame-expect: CWE-89
                return cmd.ExecuteScalar()?.ToString();
            }
        }

        public void Archive(string ledger)
        {
            Process.Start("tar", "czf /backup/" + ledger + ".tgz /var/billing/" + ledger); // frame-expect: CWE-78
        }
    }
}
