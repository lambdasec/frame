using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Xml;
using System.Xml.Serialization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace Exchange.Controllers
{
    [ApiController]
    [Route("import")]
    public class ImportController : ControllerBase
    {
        [HttpPost("xml")]
        public IActionResult FromXml([FromBody] string xml)
        {
            var doc = new XmlDocument(); // frame-expect: CWE-611
            doc.XmlResolver = new XmlUrlResolver();
            doc.LoadXml(xml);
            return Ok(doc.DocumentElement.Name);
        }

        [HttpPost("reader")]
        public IActionResult FromReader([FromBody] string xml)
        {
            var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse, XmlResolver = new XmlUrlResolver() };
            using var reader = XmlReader.Create(new StringReader(xml), settings); // frame-expect: CWE-611
            reader.Read();
            return Ok(reader.Name);
        }

        [HttpPost("legacy")]
        public IActionResult FromLegacy([FromBody] string xml)
        {
            var reader = new XmlTextReader(new StringReader(xml)); // frame-expect: CWE-611
            reader.Read();
            return Ok(reader.Name);
        }

        [HttpPost("binary")]
        public IActionResult FromBinary([FromBody] byte[] payload)
        {
            var formatter = new BinaryFormatter(); // frame-expect: CWE-502
            var obj = formatter.Deserialize(new MemoryStream(payload));
            return Ok(obj.GetType().Name);
        }

        [HttpPost("contract")]
        public IActionResult FromContract([FromBody] string xml)
        {
            var serializer = new NetDataContractSerializer(); // frame-expect: CWE-502
            var obj = serializer.ReadObject(XmlReader.Create(new StringReader(xml)));
            return Ok(obj.GetType().Name);
        }

        [HttpPost("json")]
        public IActionResult FromJson([FromBody] string json)
        {
            var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All }; // frame-expect: CWE-502
            var obj = JsonConvert.DeserializeObject(json, settings);
            return Ok(obj);
        }
    }
}
