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
                var cmd = new SqlCommand("SELECT Total FROM Orders WHERE Customer = @customer", conn);
                cmd.Parameters.AddWithValue("@customer", customer);
                return cmd.ExecuteScalar()?.ToString();
            }
        }

        public void Archive(string ledger)
        {
            var info = new ProcessStartInfo("tar");
            info.ArgumentList.Add("czf");
            info.ArgumentList.Add("/backup/archive.tgz");
            info.ArgumentList.Add("/var/billing/" + System.IO.Path.GetFileName(ledger));
            Process.Start(info);
        }
    }
}
