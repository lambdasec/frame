using System.IO;
using System.Threading.Tasks;
using Grpc.Core;

namespace Billing.Grpc
{
    public class DocumentService : Documents.DocumentsBase
    {
        public override async Task<DocumentReply> Fetch(FetchRequest request, ServerCallContext context)
        {
            var path = Path.Combine("/srv/documents", Path.GetFileName(request.Name));
            var text = await File.ReadAllTextAsync(path);
            return new DocumentReply { Body = text };
        }
    }
}
