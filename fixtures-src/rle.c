#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#define VERSION "rle-lite 1.3.2"
static void usage(FILE *f){ fprintf(f, "usage: rle [-d] [-s] [-V] TEXT\n"); }
int main(int argc, char **argv){
    int dec = 0, stats = 0; const char *text = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-d")) dec = 1;
        else if (!strcmp(argv[i], "-s")) stats = 1;
        else if (!strcmp(argv[i], "-V")) { puts(VERSION); return 0; }
        else if (!strcmp(argv[i], "-h")) { usage(stdout); return 0; }
        else text = argv[i];
    }
    if (!text) { usage(stderr); return 2; }
    size_t n = strlen(text);
    char *out = malloc(n * 100 + 2); size_t o = 0;
    if (!dec) {
        for (size_t i = 0; i < n; i++) if (isdigit((unsigned char)text[i])) { fprintf(stderr, "error: digits not allowed in input\n"); return 4; }
        for (size_t i = 0; i < n; ) {
            size_t j = i; while (j < n && text[j] == text[i] && j - i < 99) j++;
            o += sprintf(out + o, "%zu%c", j - i, text[i]); i = j;
        }
    } else {
        for (size_t i = 0; i < n; ) {
            if (!isdigit((unsigned char)text[i])) { fprintf(stderr, "error: malformed input\n"); return 3; }
            size_t c = 0; while (i < n && isdigit((unsigned char)text[i])) c = c * 10 + (text[i++] - '0');
            if (i >= n || c == 0) { fprintf(stderr, "error: malformed input\n"); return 3; }
            for (size_t k = 0; k < c; k++) out[o++] = text[i]; i++;
        }
    }
    out[o] = 0; puts(out);
    if (stats) fprintf(stderr, "in=%zu out=%zu\n", n, o);
    return 0;
}
