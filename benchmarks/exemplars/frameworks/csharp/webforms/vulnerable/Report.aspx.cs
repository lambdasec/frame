using System;
using System.Data.SqlClient;
using System.IO;
using System.Web;
using System.Web.UI;
using System.Configuration;

namespace Legacy.Web
{
    public partial class Report : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            string user = Request.QueryString["user"];
            string conStr = ConfigurationManager.ConnectionStrings["Main"].ConnectionString;
            using (var con = new SqlConnection(conStr))
            {
                con.Open();
                var cmd = new SqlCommand("SELECT * FROM Accounts WHERE Name = '" + user + "'", con); // frame-expect: CWE-89
                cmd.ExecuteReader();
            }
            Response.Write("<p>Report for " + user + "</p>"); // frame-expect: CWE-79
        }

        protected void Download_Click(object sender, EventArgs e)
        {
            string name = Request.Form["file"];
            string path = Server.MapPath("~/reports/") + name;
            Response.TransmitFile(path); // frame-expect: CWE-22
        }

        protected void Back_Click(object sender, EventArgs e)
        {
            string next = Request.Params["next"];
            Response.Redirect(next); // frame-expect: CWE-601
        }
    }
}
