using System.IO;
using System.Threading.Tasks;
using Grpc.Core;

namespace Billing.Grpc
{
    public class DocumentService : Documents.DocumentsBase
    {
        public override async Task<DocumentReply> Fetch(FetchRequest request, ServerCallContext context)
        {
            var path = Path.Combine("/srv/documents", request.Name);
            var text = await File.ReadAllTextAsync(path); // frame-expect: CWE-22
            return new DocumentReply { Body = text };
        }
    }
}
