from lxml import etree


def parse_feed(data):
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    root = etree.fromstring(data, parser)
    return {"items": [e.text for e in root.iter("item")]}


def load_compiled(blob):
    import json
    return json.loads(blob)
