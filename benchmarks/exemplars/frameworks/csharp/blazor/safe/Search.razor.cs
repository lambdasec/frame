using System.Data.SqlClient;
using System.Net;
using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.Configuration;

namespace Docs.Pages
{
    public partial class Search : ComponentBase
    {
        [Inject]
        private NavigationManager Navigation { get; set; }

        [Inject]
        private IConfiguration Config { get; set; }

        [Parameter]
        [SupplyParameterFromQuery(Name = "q")]
        public string Term { get; set; }

        [Parameter]
        [SupplyParameterFromQuery]
        public string Next { get; set; }

        public MarkupString Banner { get; set; }

        protected override void OnInitialized()
        {
            Banner = new MarkupString("<b>Results for " + WebUtility.HtmlEncode(Term) + "</b>");
        }

        protected override async System.Threading.Tasks.Task OnParametersSetAsync()
        {
            using var conn = new SqlConnection(Config.GetConnectionString("Docs"));
            await conn.OpenAsync();
            var cmd = new SqlCommand("SELECT Title FROM Pages WHERE Body LIKE @term", conn);
            cmd.Parameters.AddWithValue("@term", "%" + Term + "%");
            await cmd.ExecuteReaderAsync();
        }

        private void Continue()
        {
            if (Next != null && Next.StartsWith("/") && !Next.StartsWith("//"))
            {
                Navigation.NavigateTo(Next);
            }
        }
    }
}
