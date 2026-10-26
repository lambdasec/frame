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
                var cmd = new SqlCommand("SELECT * FROM Accounts WHERE Name = @name", con);
                cmd.Parameters.AddWithValue("@name", user);
                cmd.ExecuteReader();
            }
            Response.Write("<p>Report for " + HttpUtility.HtmlEncode(user) + "</p>");
        }

        protected void Download_Click(object sender, EventArgs e)
        {
            string name = Request.Form["file"];
            string path = Server.MapPath("~/reports/") + Path.GetFileName(name);
            Response.TransmitFile(path);
        }

        protected void Back_Click(object sender, EventArgs e)
        {
            string next = Request.Params["next"];
            if (!next.StartsWith("/") || next.StartsWith("//"))
            {
                Response.Redirect("~/Default.aspx");
                return;
            }
            Response.Redirect(next);
        }
    }
}
