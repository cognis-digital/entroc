/* entroc - windowed entropy scanner and blob/secret triage (C99, stdlib+libm only)
 *
 * Slides a window over a file (or stdin), computes multiple entropy metrics per
 * window, classifies each window's likely content class (base64 / hex / text /
 * high-entropy blob / packed binary), merges adjacent flagged windows into
 * contiguous regions, and scans for likely embedded secrets (PEM blocks, AWS
 * keys, JWTs, high-entropy key-length base64/hex runs). Output as JSON, CSV,
 * human text, or SARIF 2.1.0.
 *
 * Scope: DEFENSIVE / triage / OSINT. Secret previews are always redacted.
 *
 * Exit codes:  0 = nothing flagged   2 = something flagged   1 = error
 *
 * Build:  gcc -O2 -std=c99 -Wall -Wextra -o entroc entroc.c -lm
 *
 * Portability: strictly C99 stdlib + libm. No POSIX-only calls. Reads stdin in
 * binary via freopen where needed; builds under gcc/clang/MSVC/MinGW.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stddef.h>

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif

#define ENTROC_VERSION "2.0.0"

/* ------------------------------------------------------------------ */
/* entropy + statistics                                                */
/* ------------------------------------------------------------------ */

/* Shannon entropy in bits/byte (0..8). */
double entroc_shannon(const unsigned char *buf, size_t n) {
    if (n == 0) return 0.0;
    size_t freq[256] = {0};
    for (size_t i = 0; i < n; i++) freq[buf[i]]++;
    double h = 0.0;
    for (int b = 0; b < 256; b++) {
        if (!freq[b]) continue;
        double p = (double)freq[b] / (double)n;
        h -= p * log2(p);
    }
    return h;
}

/* Min-entropy H_inf = -log2(max p_i), in bits/byte (0..8). */
double entroc_min_entropy(const unsigned char *buf, size_t n) {
    if (n == 0) return 0.0;
    size_t freq[256] = {0};
    for (size_t i = 0; i < n; i++) freq[buf[i]]++;
    size_t maxf = 0;
    for (int b = 0; b < 256; b++) if (freq[b] > maxf) maxf = freq[b];
    if (maxf == 0) return 0.0;
    double pmax = (double)maxf / (double)n;
    return -log2(pmax);
}

/* Pearson chi-square statistic vs uniform-over-256 distribution.
 * Lower ~= more uniform (more random). Expected per bucket = n/256.
 * For truly uniform data the expected value of the statistic is 255. */
double entroc_chi_square(const unsigned char *buf, size_t n) {
    if (n == 0) return 0.0;
    size_t freq[256] = {0};
    for (size_t i = 0; i < n; i++) freq[buf[i]]++;
    double expected = (double)n / 256.0;
    double chi = 0.0;
    for (int b = 0; b < 256; b++) {
        double diff = (double)freq[b] - expected;
        chi += (diff * diff) / expected;
    }
    return chi;
}

/* ------------------------------------------------------------------ */
/* content classification                                              */
/* ------------------------------------------------------------------ */

typedef enum {
    CLS_TEXT = 0,       /* printable ASCII / whitespace dominated */
    CLS_BASE64,         /* base64 alphabet dominated */
    CLS_HEX,            /* hex alphabet dominated */
    CLS_HIGH_ENTROPY,   /* compressed / encrypted */
    CLS_PACKED,         /* binary, moderately high entropy */
    CLS_BINARY          /* low/moderate entropy binary */
} entroc_class_t;

static const char *class_name(entroc_class_t c) {
    switch (c) {
        case CLS_TEXT:         return "text";
        case CLS_BASE64:       return "base64";
        case CLS_HEX:          return "hex";
        case CLS_HIGH_ENTROPY: return "high-entropy";
        case CLS_PACKED:       return "packed-binary";
        case CLS_BINARY:       return "binary";
    }
    return "binary";
}

static int is_base64_char(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' ||
           c == '-' || c == '_'; /* url-safe */
}
static int is_hex_char(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
static int is_printable(unsigned char c) {
    return (c >= 0x20 && c <= 0x7e) || c == '\t' || c == '\n' || c == '\r';
}

/* Classify a window using character-class ratios + entropy. */
entroc_class_t entroc_classify(const unsigned char *buf, size_t n, double shannon) {
    if (n == 0) return CLS_BINARY;
    size_t b64 = 0, hex = 0, print = 0, alnum = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = buf[i];
        if (is_base64_char(c)) b64++;
        if (is_hex_char(c)) hex++;
        if (is_printable(c)) print++;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) alnum++;
    }
    double rb64 = (double)b64 / (double)n;
    double rhex = (double)hex / (double)n;
    double rprint = (double)print / (double)n;
    double ralnum = (double)alnum / (double)n;

    /* Hex is the most specific: nearly all chars from the 16-symbol hex set. */
    if (rhex >= 0.95 && ralnum >= 0.9) return CLS_HEX;
    /* Base64: almost entirely base64 alphabet and reasonably dense entropy. */
    if (rb64 >= 0.95 && ralnum >= 0.85 && shannon >= 3.5) return CLS_BASE64;
    /* Printable text with modest entropy. */
    if (rprint >= 0.90 && shannon < 6.0) return CLS_TEXT;
    /* Not text: split by entropy. */
    if (shannon >= 7.5) return CLS_HIGH_ENTROPY;
    if (shannon >= 6.5) return CLS_PACKED;
    return CLS_BINARY;
}

/* ------------------------------------------------------------------ */
/* secret detection                                                    */
/* ------------------------------------------------------------------ */

typedef struct {
    size_t offset;
    size_t length;
    char kind[32];        /* e.g. "pem", "aws-access-key", "jwt" */
    char preview[48];     /* REDACTED preview, never the full secret */
} entroc_secret_t;

/* Build a redacted preview: first up to 4 visible chars, then "...redacted..." */
static void make_preview(char *dst, size_t dstsz, const unsigned char *s, size_t n) {
    size_t shown = n < 4 ? n : 4;
    size_t j = 0;
    for (size_t i = 0; i < shown && j + 1 < dstsz; i++) {
        unsigned char c = s[i];
        dst[j++] = (c >= 0x20 && c <= 0x7e && c != '"' && c != '\\') ? (char)c : '.';
    }
    const char *tail = "...[redacted]";
    for (size_t k = 0; tail[k] && j + 1 < dstsz; k++) dst[j++] = tail[k];
    dst[j] = '\0';
}

/* case-insensitive-ish substring within a byte buffer (no NUL assumptions) */
static const unsigned char *mem_find(const unsigned char *hay, size_t hn,
                                     const char *needle) {
    size_t nn = strlen(needle);
    if (nn == 0 || hn < nn) return NULL;
    for (size_t i = 0; i + nn <= hn; i++) {
        if (memcmp(hay + i, needle, nn) == 0) return hay + i;
    }
    return NULL;
}

/* Run length of consecutive base64 chars starting at i. */
static size_t b64_run(const unsigned char *data, size_t n, size_t i) {
    size_t j = i;
    while (j < n && is_base64_char(data[j])) j++;
    return j - i;
}
static size_t hex_run(const unsigned char *data, size_t n, size_t i) {
    size_t j = i;
    while (j < n && is_hex_char(data[j])) j++;
    return j - i;
}

/* Append a secret to a growable list. */
static int push_secret(entroc_secret_t **arr, size_t *count, size_t *cap,
                       size_t off, size_t len, const char *kind,
                       const unsigned char *data) {
    if (*count == *cap) {
        size_t ncap = *cap ? *cap * 2 : 16;
        entroc_secret_t *na = realloc(*arr, ncap * sizeof(**arr));
        if (!na) return -1;
        *arr = na; *cap = ncap;
    }
    entroc_secret_t *s = &(*arr)[*count];
    s->offset = off;
    s->length = len;
    snprintf(s->kind, sizeof s->kind, "%s", kind);
    make_preview(s->preview, sizeof s->preview, data + off, len);
    (*count)++;
    return 0;
}

/* Detect if a candidate looks like a JWT: three base64url segments split by '.'
 * starting with "eyJ". Returns total length if so, else 0. */
static size_t jwt_len(const unsigned char *data, size_t n, size_t i) {
    if (i + 3 >= n || memcmp(data + i, "eyJ", 3) != 0) return 0;
    size_t seg = 0, dots = 0, j = i;
    size_t cur = 0;
    while (j < n) {
        unsigned char c = data[j];
        if (is_base64_char(c) && c != '=') { cur++; j++; }
        else if (c == '.') { if (cur == 0) break; dots++; seg++; cur = 0; j++; }
        else break;
    }
    if (cur > 0) seg++;
    if (dots == 2 && seg == 3 && (j - i) >= 20) return j - i;
    return 0;
}

/* Scan whole buffer for embedded secrets. Returns count; fills *out (caller frees). */
size_t entroc_scan_secrets(const unsigned char *data, size_t n, entroc_secret_t **out) {
    entroc_secret_t *arr = NULL;
    size_t count = 0, cap = 0;
    *out = NULL;

    /* PEM blocks: -----BEGIN <label>----- ... -----END <label>----- */
    size_t i = 0;
    while (i < n) {
        const unsigned char *hit = mem_find(data + i, n - i, "-----BEGIN ");
        if (!hit) break;
        size_t start = (size_t)(hit - data);
        const unsigned char *endm = mem_find(data + start, n - start, "-----END ");
        size_t blocklen;
        if (endm) {
            size_t es = (size_t)(endm - data);
            const unsigned char *close = mem_find(data + es, n - es, "-----");
            size_t after = close ? (size_t)(close - data) + 5 : es;
            /* skip past the closing dashes plus any trailing dashes */
            while (after < n && data[after] == '-') after++;
            blocklen = after - start;
        } else {
            blocklen = n - start; /* unterminated; report to end */
        }
        push_secret(&arr, &count, &cap, start, blocklen, "pem-block", data);
        i = start + (blocklen ? blocklen : 1);
    }

    /* Byte-wise scan for AWS keys, JWTs, long hex, long base64 key material. */
    for (size_t p = 0; p < n; p++) {
        /* AWS access key id: AKIA / ASIA + 16 uppercase alnum (total 20). */
        if (p + 20 <= n &&
            ((memcmp(data + p, "AKIA", 4) == 0) || (memcmp(data + p, "ASIA", 4) == 0))) {
            int ok = 1;
            for (size_t k = 4; k < 20; k++) {
                unsigned char c = data[p + k];
                if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))) { ok = 0; break; }
            }
            /* boundary: not preceded/followed by more alnum */
            if (ok && (p + 20 >= n || !((data[p+20] >= 'A' && data[p+20] <= 'Z') ||
                                        (data[p+20] >= '0' && data[p+20] <= '9')))) {
                push_secret(&arr, &count, &cap, p, 20, "aws-access-key-id", data);
                p += 19;
                continue;
            }
        }
        /* JWT */
        size_t jl = jwt_len(data, n, p);
        if (jl) {
            push_secret(&arr, &count, &cap, p, jl, "jwt", data);
            p += jl - 1;
            continue;
        }
        /* long hex run: >=32 hex chars with high alphabet spread => key/hash-like */
        {
            size_t hr = hex_run(data, n, p);
            if (hr >= 32) {
                /* boundary check: not part of a longer alnum-ish token beyond hex */
                double h = entroc_shannon(data + p, hr);
                if (h >= 3.0) { /* avoid all-zero hex like 0000... */
                    const char *kind = (hr == 32) ? "hex-32" :
                                       (hr == 40) ? "hex-40-sha1" :
                                       (hr == 64) ? "hex-64-sha256" : "hex-long";
                    push_secret(&arr, &count, &cap, p, hr, kind, data);
                }
                p += hr - 1;
                continue;
            }
        }
        /* long base64 run of key-like length (>=40) and high entropy */
        {
            size_t br = b64_run(data, n, p);
            if (br >= 40) {
                double h = entroc_shannon(data + p, br);
                if (h >= 4.5) {
                    push_secret(&arr, &count, &cap, p, br, "base64-key-material", data);
                }
                p += br - 1;
                continue;
            }
        }
    }

    *out = arr;
    return count;
}

/* ------------------------------------------------------------------ */
/* window scan + region merge                                          */
/* ------------------------------------------------------------------ */

typedef struct {
    size_t offset;
    size_t length;
    double entropy;      /* max shannon within region */
    entroc_class_t cls;  /* class of the strongest window */
} entroc_region_t;

typedef struct {
    size_t offset;
    size_t length;
    double shannon;
    double min_entropy;
    double chi_square;
    entroc_class_t cls;
    int flagged;
} entroc_window_t;

/* The following helpers and main() are only compiled for the CLI. Defining
 * ENTROC_NO_MAIN (used by the unit test) drops them so the library functions
 * can be linked standalone with no unused-function warnings. */
#ifndef ENTROC_NO_MAIN

/* ------------------------------------------------------------------ */
/* I/O: read a whole stream (stdin or file) into a growable buffer      */
/* ------------------------------------------------------------------ */

static unsigned char *read_stream(FILE *f, size_t *out_len) {
    size_t cap = 1 << 16, len = 0;
    unsigned char *buf = malloc(cap);
    if (!buf) return NULL;
    for (;;) {
        if (len == cap) {
            size_t ncap = cap * 2;
            unsigned char *nb = realloc(buf, ncap);
            if (!nb) { free(buf); return NULL; }
            buf = nb; cap = ncap;
        }
        size_t got = fread(buf + len, 1, cap - len, f);
        len += got;
        if (got == 0) {
            if (feof(f)) break;
            if (ferror(f)) { free(buf); return NULL; }
        }
    }
    *out_len = len;
    return buf;
}

/* ------------------------------------------------------------------ */
/* JSON string escaping                                                */
/* ------------------------------------------------------------------ */

static void json_puts(FILE *o, const char *s) {
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
            case '"':  fputs("\\\"", o); break;
            case '\\': fputs("\\\\", o); break;
            case '\n': fputs("\\n", o); break;
            case '\r': fputs("\\r", o); break;
            case '\t': fputs("\\t", o); break;
            default:
                if (c < 0x20) fprintf(o, "\\u%04x", c);
                else fputc((int)c, o);
        }
    }
}

/* ------------------------------------------------------------------ */
/* help                                                                */
/* ------------------------------------------------------------------ */

static void usage(FILE *o) {
    fputs(
"entroc " ENTROC_VERSION " - windowed entropy scanner & blob/secret triage\n"
"\n"
"USAGE:\n"
"  entroc <file|-> [options]      ('-' reads stdin)\n"
"\n"
"WINDOWING:\n"
"  --window N       window size in bytes            (default 256)\n"
"  --step N         advance between windows          (default = window)\n"
"  --threshold F    min Shannon bits/byte to flag    (default 7.0)\n"
"  --min-region N   drop merged regions shorter than N bytes (default 0)\n"
"\n"
"OUTPUT:\n"
"  --format FMT     json (default) | csv | text | sarif\n"
"  --profile        include per-window entropy series in output\n"
"  --sparkline      draw an ASCII entropy sparkline to stderr\n"
"  --no-secrets     disable embedded-secret scanning\n"
"\n"
"METRICS reported per window and file-global:\n"
"  Shannon entropy (0..8 bits/byte), min-entropy H_inf, chi-square vs uniform.\n"
"\n"
"DETECTORS:\n"
"  Content class per window: text / base64 / hex / high-entropy / packed-binary.\n"
"  Embedded secrets: PEM blocks, AWS access-key ids, JWTs, long hex, base64 key\n"
"  material. Previews are always REDACTED.\n"
"\n"
"EXIT CODES:\n"
"  0  nothing flagged      2  region(s) or secret(s) flagged      1  error\n"
"\n"
"Defensive / triage / OSINT use only.\n", o);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

typedef enum { FMT_JSON, FMT_CSV, FMT_TEXT, FMT_SARIF } fmt_t;

int main(int argc, char **argv) {
    const char *path = NULL;
    size_t window = 256, step = 0, min_region = 0;
    double threshold = 7.0;
    fmt_t fmt = FMT_JSON;
    int profile = 0, sparkline = 0, scan_secrets = 1;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--window") == 0 && i + 1 < argc) window = (size_t)strtoul(argv[++i], NULL, 10);
        else if (strcmp(a, "--step") == 0 && i + 1 < argc) step = (size_t)strtoul(argv[++i], NULL, 10);
        else if (strcmp(a, "--threshold") == 0 && i + 1 < argc) threshold = atof(argv[++i]);
        else if (strcmp(a, "--min-region") == 0 && i + 1 < argc) min_region = (size_t)strtoul(argv[++i], NULL, 10);
        else if (strcmp(a, "--format") == 0 && i + 1 < argc) {
            const char *f = argv[++i];
            if (strcmp(f, "json") == 0) fmt = FMT_JSON;
            else if (strcmp(f, "csv") == 0) fmt = FMT_CSV;
            else if (strcmp(f, "text") == 0) fmt = FMT_TEXT;
            else if (strcmp(f, "sarif") == 0) fmt = FMT_SARIF;
            else { fprintf(stderr, "entroc: unknown format '%s'\n", f); return 1; }
        }
        else if (strcmp(a, "--profile") == 0) profile = 1;
        else if (strcmp(a, "--sparkline") == 0) sparkline = 1;
        else if (strcmp(a, "--no-secrets") == 0) scan_secrets = 0;
        else if (strcmp(a, "--version") == 0) { printf("entroc %s\n", ENTROC_VERSION); return 0; }
        else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) { usage(stdout); return 0; }
        else if (strcmp(a, "-") == 0) path = "-";
        else if (a[0] != '-') path = a;
        else { fprintf(stderr, "entroc: unknown option '%s'\n", a); return 1; }
    }
    if (!path) { fprintf(stderr, "entroc: no input file (use '-' for stdin)\n"); usage(stderr); return 1; }
    if (window == 0) window = 256;
    if (step == 0) step = window;

    /* read input */
    unsigned char *data = NULL;
    size_t got = 0;
    if (strcmp(path, "-") == 0) {
#ifdef _WIN32
        _setmode(_fileno(stdin), _O_BINARY);
#endif
        data = read_stream(stdin, &got);
        if (!data) { fprintf(stderr, "entroc: cannot read stdin\n"); return 1; }
    } else {
        FILE *f = fopen(path, "rb");
        if (!f) { fprintf(stderr, "entroc: cannot open %s\n", path); return 1; }
        data = read_stream(f, &got);
        fclose(f);
        if (!data) { fprintf(stderr, "entroc: cannot read %s\n", path); return 1; }
    }

    /* file-global metrics */
    double g_shannon = entroc_shannon(data, got);
    double g_min = entroc_min_entropy(data, got);
    double g_chi = entroc_chi_square(data, got);

    /* window scan */
    size_t win_cap = 16, win_count = 0;
    entroc_window_t *wins = malloc(win_cap * sizeof *wins);
    if (!wins) { free(data); fprintf(stderr, "entroc: oom\n"); return 1; }

    double max_h = 0.0;
    for (size_t off = 0; off < got; off += step) {
        size_t n = (off + window <= got) ? window : (got - off);
        if (n == 0) break;
        double h = entroc_shannon(data + off, n);
        if (h > max_h) max_h = h;
        if (win_count == win_cap) {
            win_cap *= 2;
            entroc_window_t *nw = realloc(wins, win_cap * sizeof *wins);
            if (!nw) { free(wins); free(data); fprintf(stderr, "entroc: oom\n"); return 1; }
            wins = nw;
        }
        entroc_window_t *w = &wins[win_count++];
        w->offset = off;
        w->length = n;
        w->shannon = h;
        w->min_entropy = entroc_min_entropy(data + off, n);
        w->chi_square = entroc_chi_square(data + off, n);
        w->cls = entroc_classify(data + off, n, h);
        w->flagged = (h >= threshold) ? 1 : 0;
        if (n < window) break;
    }

    /* merge adjacent flagged windows into regions */
    size_t reg_cap = 8, reg_count = 0;
    entroc_region_t *regs = malloc(reg_cap * sizeof *regs);
    if (!regs) { free(wins); free(data); fprintf(stderr, "entroc: oom\n"); return 1; }
    for (size_t i = 0; i < win_count; i++) {
        if (!wins[i].flagged) continue;
        size_t rstart = wins[i].offset;
        size_t rend = wins[i].offset + wins[i].length;
        double rmax = wins[i].shannon;
        entroc_class_t rcls = wins[i].cls;
        while (i + 1 < win_count && wins[i+1].flagged &&
               wins[i+1].offset <= rend) {
            i++;
            size_t e = wins[i].offset + wins[i].length;
            if (e > rend) rend = e;
            if (wins[i].shannon > rmax) { rmax = wins[i].shannon; rcls = wins[i].cls; }
        }
        size_t rlen = rend - rstart;
        if (rlen < min_region) continue;
        if (reg_count == reg_cap) {
            reg_cap *= 2;
            entroc_region_t *nr = realloc(regs, reg_cap * sizeof *regs);
            if (!nr) { free(regs); free(wins); free(data); fprintf(stderr, "entroc: oom\n"); return 1; }
            regs = nr;
        }
        regs[reg_count].offset = rstart;
        regs[reg_count].length = rlen;
        regs[reg_count].entropy = rmax;
        regs[reg_count].cls = rcls;
        reg_count++;
    }

    /* secrets */
    entroc_secret_t *secrets = NULL;
    size_t secret_count = 0;
    if (scan_secrets) secret_count = entroc_scan_secrets(data, got, &secrets);

    int flagged = (reg_count > 0 || secret_count > 0) ? 1 : 0;

    /* optional sparkline to stderr */
    if (sparkline && win_count > 0) {
        static const char *ramp = " .:-=+*#%@";
        fputs("entropy: ", stderr);
        for (size_t i = 0; i < win_count; i++) {
            int idx = (int)(wins[i].shannon / 8.0 * 9.0);
            if (idx < 0) idx = 0;
            if (idx > 9) idx = 9;
            fputc(ramp[idx], stderr);
        }
        fputc('\n', stderr);
    }

    /* ---------------- output ---------------- */
    if (fmt == FMT_JSON) {
        FILE *o = stdout;
        fputs("{\"tool\":\"entroc\",\"version\":\"" ENTROC_VERSION "\",\"file\":\"", o);
        json_puts(o, strcmp(path, "-") == 0 ? "<stdin>" : path);
        fprintf(o, "\",\"size\":%zu,\"window\":%zu,\"step\":%zu,\"threshold\":%.2f,",
                got, window, step, threshold);
        fprintf(o, "\"global\":{\"shannon\":%.4f,\"min_entropy\":%.4f,\"chi_square\":%.2f},",
                g_shannon, g_min, g_chi);
        fprintf(o, "\"max_entropy\":%.4f,\"regions\":[", max_h);
        for (size_t i = 0; i < reg_count; i++) {
            fprintf(o, "%s{\"offset\":%zu,\"length\":%zu,\"entropy\":%.4f,\"class\":\"%s\"}",
                    i ? "," : "", regs[i].offset, regs[i].length, regs[i].entropy,
                    class_name(regs[i].cls));
        }
        fprintf(o, "],\"regions_flagged\":%zu,\"secrets\":[", reg_count);
        for (size_t i = 0; i < secret_count; i++) {
            fprintf(o, "%s{\"offset\":%zu,\"length\":%zu,\"kind\":\"", i ? "," : "",
                    secrets[i].offset, secrets[i].length);
            json_puts(o, secrets[i].kind);
            fputs("\",\"preview\":\"", o);
            json_puts(o, secrets[i].preview);
            fputs("\"}", o);
        }
        fprintf(o, "],\"secrets_flagged\":%zu", secret_count);
        if (profile) {
            fputs(",\"profile\":[", o);
            for (size_t i = 0; i < win_count; i++) {
                fprintf(o, "%s{\"offset\":%zu,\"shannon\":%.4f,\"min_entropy\":%.4f,\"chi_square\":%.2f,\"class\":\"%s\"}",
                        i ? "," : "", wins[i].offset, wins[i].shannon,
                        wins[i].min_entropy, wins[i].chi_square, class_name(wins[i].cls));
            }
            fputc(']', o);
        }
        fputs("}\n", o);
    } else if (fmt == FMT_CSV) {
        FILE *o = stdout;
        if (profile) {
            printf("type,offset,length,shannon,min_entropy,chi_square,class\n");
            for (size_t i = 0; i < win_count; i++) {
                fprintf(o, "window,%zu,%zu,%.4f,%.4f,%.2f,%s\n",
                        wins[i].offset, wins[i].length, wins[i].shannon,
                        wins[i].min_entropy, wins[i].chi_square, class_name(wins[i].cls));
            }
        } else {
            printf("type,offset,length,entropy,class,detail\n");
        }
        for (size_t i = 0; i < reg_count; i++) {
            fprintf(o, "region,%zu,%zu,%.4f,%s,\n",
                    regs[i].offset, regs[i].length, regs[i].entropy, class_name(regs[i].cls));
        }
        for (size_t i = 0; i < secret_count; i++) {
            fprintf(o, "secret,%zu,%zu,,%s,%s\n",
                    secrets[i].offset, secrets[i].length, secrets[i].kind, secrets[i].preview);
        }
    } else if (fmt == FMT_TEXT) {
        FILE *o = stdout;
        fprintf(o, "entroc %s  file=%s  size=%zu bytes\n", ENTROC_VERSION,
                strcmp(path, "-") == 0 ? "<stdin>" : path, got);
        fprintf(o, "global: shannon=%.4f bits/byte  min-entropy=%.4f  chi-square=%.2f  max-window=%.4f\n",
                g_shannon, g_min, g_chi, max_h);
        fprintf(o, "flagged regions (>= %.2f bits/byte, merged): %zu\n", threshold, reg_count);
        for (size_t i = 0; i < reg_count; i++) {
            fprintf(o, "  [%zu] offset=%zu length=%zu entropy=%.4f class=%s\n",
                    i, regs[i].offset, regs[i].length, regs[i].entropy, class_name(regs[i].cls));
        }
        fprintf(o, "embedded secrets: %zu\n", secret_count);
        for (size_t i = 0; i < secret_count; i++) {
            fprintf(o, "  [%zu] offset=%zu length=%zu kind=%s preview=%s\n",
                    i, secrets[i].offset, secrets[i].length, secrets[i].kind, secrets[i].preview);
        }
        fprintf(o, "result: %s\n", flagged ? "FLAGGED" : "clean");
    } else { /* SARIF 2.1.0 */
        FILE *o = stdout;
        const char *fname = strcmp(path, "-") == 0 ? "stdin" : path;
        fputs("{\"$schema\":\"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json\",", o);
        fputs("\"version\":\"2.1.0\",\"runs\":[{", o);
        fputs("\"tool\":{\"driver\":{\"name\":\"entroc\",\"version\":\"" ENTROC_VERSION "\",", o);
        fputs("\"informationUri\":\"https://github.com/cognis-digital/entroc\",\"rules\":[", o);
        fputs("{\"id\":\"high-entropy-region\",\"name\":\"HighEntropyRegion\",\"shortDescription\":{\"text\":\"High-entropy region (possible packed/encrypted/compressed data)\"}},", o);
        fputs("{\"id\":\"embedded-secret\",\"name\":\"EmbeddedSecret\",\"shortDescription\":{\"text\":\"Likely embedded secret or key material\"}}", o);
        fputs("]}},\"results\":[", o);
        int first = 1;
        for (size_t i = 0; i < reg_count; i++) {
            fprintf(o, "%s{\"ruleId\":\"high-entropy-region\",\"level\":\"warning\",\"message\":{\"text\":\"", first ? "" : ",");
            first = 0;
            fprintf(o, "High-entropy %s region, entropy %.4f bits/byte\"},", class_name(regs[i].cls), regs[i].entropy);
            fputs("\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":\"", o);
            json_puts(o, fname);
            fprintf(o, "\"},\"region\":{\"byteOffset\":%zu,\"byteLength\":%zu}}}]}",
                    regs[i].offset, regs[i].length);
        }
        for (size_t i = 0; i < secret_count; i++) {
            fprintf(o, "%s{\"ruleId\":\"embedded-secret\",\"level\":\"error\",\"message\":{\"text\":\"", first ? "" : ",");
            first = 0;
            fputs("Likely embedded secret (", o);
            json_puts(o, secrets[i].kind);
            fputs("), preview ", o);
            json_puts(o, secrets[i].preview);
            fputs("\"},\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":\"", o);
            json_puts(o, fname);
            fprintf(o, "\"},\"region\":{\"byteOffset\":%zu,\"byteLength\":%zu}}}]}",
                    secrets[i].offset, secrets[i].length);
        }
        fputs("]}]}\n", o);
    }

    free(secrets);
    free(regs);
    free(wins);
    free(data);
    return flagged ? 2 : 0;
}
#endif /* ENTROC_NO_MAIN */
