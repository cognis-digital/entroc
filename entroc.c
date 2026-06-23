/* entroc — windowed Shannon-entropy scanner (C, C99, stdlib-only)
 * Part of the Cognis Neural Suite. Single-purpose, JSON-out, CI-tested.
 *
 * Flags high-entropy regions in a file (packed/encrypted/compressed blobs,
 * embedded keys/certs). Slides a fixed window over the file and reports each
 * window whose byte-entropy (0..8 bits) meets a threshold.
 *
 * Usage:
 *   entroc <file> [--window N] [--threshold F] [--step N]
 *     --window     window size in bytes        (default 256)
 *     --step       advance between windows      (default = window)
 *     --threshold  min entropy in bits to flag  (default 7.0)
 *
 * Output: JSON object on stdout. Exit 2 if any region flagged, 0 otherwise,
 *         1 on error.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

static double window_entropy(const unsigned char *buf, size_t n) {
    if (n == 0) return 0.0;
    size_t freq[256] = {0};
    for (size_t i = 0; i < n; i++) freq[buf[i]]++;
    double h = 0.0;
    for (int b = 0; b < 256; b++) {
        if (!freq[b]) continue;
        double p = (double)freq[b] / (double)n;
        h -= p * log2(p);
    }
    return h; /* bits per byte, 0..8 */
}

int main(int argc, char **argv) {
    const char *path = NULL;
    size_t window = 256, step = 0;
    double threshold = 7.0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--window") == 0 && i + 1 < argc) window = (size_t)strtoul(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--step") == 0 && i + 1 < argc) step = (size_t)strtoul(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--threshold") == 0 && i + 1 < argc) threshold = atof(argv[++i]);
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            fprintf(stderr, "usage: entroc <file> [--window N] [--step N] [--threshold F]\n");
            return 0;
        } else if (argv[i][0] != '-') path = argv[i];
    }
    if (!path) { fprintf(stderr, "entroc: no input file\n"); return 1; }
    if (window == 0) window = 256;
    if (step == 0) step = window;

    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "entroc: cannot open %s\n", path); return 1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); fprintf(stderr, "entroc: cannot size %s\n", path); return 1; }

    unsigned char *data = malloc((size_t)sz ? (size_t)sz : 1);
    if (!data) { fclose(f); fprintf(stderr, "entroc: oom\n"); return 1; }
    size_t got = fread(data, 1, (size_t)sz, f);
    fclose(f);

    printf("{\"tool\":\"entroc\",\"file\":\"%s\",\"size\":%zu,\"window\":%zu,\"threshold\":%.2f,\"regions\":[",
           path, got, window, threshold);

    int flagged = 0, first = 1;
    double max_h = 0.0;
    for (size_t off = 0; off + 1 <= got; off += step) {
        size_t n = (off + window <= got) ? window : (got - off);
        if (n == 0) break;
        double h = window_entropy(data + off, n);
        if (h > max_h) max_h = h;
        if (h >= threshold) {
            printf("%s{\"offset\":%zu,\"length\":%zu,\"entropy\":%.4f}", first ? "" : ",", off, n, h);
            first = 0;
            flagged++;
        }
        if (n < window) break;
    }
    printf("],\"regions_flagged\":%d,\"max_entropy\":%.4f}\n", flagged, max_h);

    free(data);
    return flagged ? 2 : 0;
}
