/* Order-import service: clients POST an XML order over a socket; we parse it with libxml2. */
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define MAX_DOC 65536

static void print_order(xmlDocPtr doc) {
    xmlNodePtr root = xmlDocGetRootElement(doc);
    for (xmlNodePtr n = root ? root->children : NULL; n; n = n->next) {
        if (n->type != XML_ELEMENT_NODE)
            continue;
        xmlChar *text = xmlNodeGetContent(n);
        printf("%s = %s\n", (const char *) n->name, (const char *) text);
        xmlFree(text);
    }
}

int handle_order(int client) {
    static char doc_buf[MAX_DOC];
    ssize_t len = recv(client, doc_buf, sizeof(doc_buf), 0);
    if (len <= 0)
        return -1;

    xmlDocPtr doc = xmlReadMemory(doc_buf, (int) len, "order.xml", NULL, /* frame-expect: CWE-611 */
                                  XML_PARSE_NOENT | XML_PARSE_DTDLOAD);
    if (!doc)
        return -1;
    print_order(doc);
    xmlFreeDoc(doc);
    return 0;
}

int handle_batch(int client) {
    static char batch_buf[MAX_DOC];
    ssize_t len = recv(client, batch_buf, sizeof(batch_buf), 0);
    if (len <= 0)
        return -1;

    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    xmlDocPtr doc = xmlCtxtReadMemory(ctxt, batch_buf, (int) len, "batch.xml", NULL, /* frame-expect: CWE-611 */
                                      XML_PARSE_DTDLOAD | XML_PARSE_NOBLANKS);
    xmlFreeParserCtxt(ctxt);
    if (!doc)
        return -1;
    print_order(doc);
    xmlFreeDoc(doc);
    return 0;
}
