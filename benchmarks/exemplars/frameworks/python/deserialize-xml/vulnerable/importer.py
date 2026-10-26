import marshal

from lxml import etree


def parse_feed(data):
    parser = etree.XMLParser(resolve_entities=True, load_dtd=True)
    root = etree.fromstring(data, parser)  # frame-expect: CWE-611
    return {"items": [e.text for e in root.iter("item")]}


def load_compiled(blob):
    return marshal.loads(blob)  # frame-expect: CWE-502
