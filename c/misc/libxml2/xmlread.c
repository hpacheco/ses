#include "libxml/parser.h"
#include "libxml/tree.h"
#include <unistd.h>

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
    #ifdef __AFL_HAVE_MANUAL_CONTROL
        __AFL_INIT();
    #endif
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;  // must be after __AFL_INIT

    xmlInitParser();
    while (__AFL_LOOP(1000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        xmlDocPtr doc = xmlReadMemory((char *)buf, len, "https://mykter.com", NULL, 0);
        if (doc != NULL) {
            xmlFreeDoc(doc);
        }
    }
    xmlCleanupParser();

    return(0);
}
