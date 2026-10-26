using System.Data.SqlClient;
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
            Banner = new MarkupString("<b>Results for " + Term + "</b>"); // frame-expect: CWE-79
        }

        protected override async System.Threading.Tasks.Task OnParametersSetAsync()
        {
            using var conn = new SqlConnection(Config.GetConnectionString("Docs"));
            await conn.OpenAsync();
            var cmd = new SqlCommand("SELECT Title FROM Pages WHERE Body LIKE '%" + Term + "%'", conn); // frame-expect: CWE-89
            await cmd.ExecuteReaderAsync();
        }

        private void Continue()
        {
            Navigation.NavigateTo(Next); // frame-expect: CWE-601
        }
    }
}
