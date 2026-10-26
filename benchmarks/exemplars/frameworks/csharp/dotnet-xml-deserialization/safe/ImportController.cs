using System.IO;
using System.Runtime.Serialization;
using System.Text.Json;
using System.Xml;
using System.Xml.Serialization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace Exchange.Controllers
{
    public record Manifest(string Name, int Count);

    [ApiController]
    [Route("import")]
    public class ImportController : ControllerBase
    {
        [HttpPost("xml")]
        public IActionResult FromXml([FromBody] string xml)
        {
            var doc = new XmlDocument();
            doc.XmlResolver = null;
            doc.LoadXml(xml);
            return Ok(doc.DocumentElement.Name);
        }

        [HttpPost("reader")]
        public IActionResult FromReader([FromBody] string xml)
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
            using var reader = XmlReader.Create(new StringReader(xml), settings);
            reader.Read();
            return Ok(reader.Name);
        }

        [HttpPost("legacy")]
        public IActionResult FromLegacy([FromBody] string xml)
        {
            var reader = new XmlTextReader(new StringReader(xml)) { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
            reader.Read();
            return Ok(reader.Name);
        }

        [HttpPost("binary")]
        public IActionResult FromBinary([FromBody] byte[] payload)
        {
            var manifest = System.Text.Json.JsonSerializer.Deserialize<Manifest>(payload);
            return Ok(manifest.Name);
        }

        [HttpPost("contract")]
        public IActionResult FromContract([FromBody] string xml)
        {
            var serializer = new DataContractSerializer(typeof(Manifest));
            var obj = serializer.ReadObject(XmlReader.Create(new StringReader(xml)));
            return Ok(obj.GetType().Name);
        }

        [HttpPost("json")]
        public IActionResult FromJson([FromBody] string json)
        {
            var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None };
            var obj = JsonConvert.DeserializeObject<Manifest>(json, settings);
            return Ok(obj);
        }
    }
}
