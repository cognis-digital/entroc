/* unit_entropy.c - link the entroc entropy/detector functions directly and
 * assert known values. Build:
 *   gcc -std=c99 -Wall -Wextra -Werror -DENTROC_NO_MAIN \
 *       -I.. -o unit_entropy unit_entropy.c -lm
 * (entroc.c is #included with main() compiled out.)
 */
#include <stdio.h>
#include <string.h>
#include <math.h>

#define ENTROC_NO_MAIN
#include "../entroc.c"

static int failures = 0;
static int checks = 0;

static void approx(const char *name, double got, double want, double eps) {
    checks++;
    if (fabs(got - want) <= eps) {
        printf("PASS %s (got %.6f, want %.6f)\n", name, got, want);
    } else {
        printf("FAIL %s (got %.6f, want %.6f, eps %.6f)\n", name, got, want, eps);
        failures++;
    }
}

static void eq_sz(const char *name, size_t got, size_t want) {
    checks++;
    if (got == want) {
        printf("PASS %s (got %zu)\n", name, got);
    } else {
        printf("FAIL %s (got %zu, want %zu)\n", name, got, want);
        failures++;
    }
}

static void eq_str(const char *name, const char *got, const char *want) {
    checks++;
    if (strcmp(got, want) == 0) {
        printf("PASS %s (got \"%s\")\n", name, got);
    } else {
        printf("FAIL %s (got \"%s\", want \"%s\")\n", name, got, want);
        failures++;
    }
}

int main(void) {
    /* Shannon entropy */
    unsigned char zeros[256] = {0};
    approx("shannon(all-zeros)=0", entroc_shannon(zeros, 256), 0.0, 1e-9);

    unsigned char uniform[256];
    for (int i = 0; i < 256; i++) uniform[i] = (unsigned char)i;
    approx("shannon(0..255 uniform)=8", entroc_shannon(uniform, 256), 8.0, 1e-9);

    /* Two equiprobable symbols => 1 bit/byte */
    unsigned char two[4] = { 'A', 'B', 'A', 'B' };
    approx("shannon(ABAB)=1", entroc_shannon(two, 4), 1.0, 1e-9);

    /* Min-entropy */
    approx("min_entropy(all-zeros)=0", entroc_min_entropy(zeros, 256), 0.0, 1e-9);
    approx("min_entropy(0..255 uniform)=8", entroc_min_entropy(uniform, 256), 8.0, 1e-9);
    /* AABB: max p = 0.5 -> H_inf = 1 */
    approx("min_entropy(ABAB)=1", entroc_min_entropy(two, 4), 1.0, 1e-9);
    /* AAAB: max p = 0.75 -> H_inf = -log2(0.75) ~= 0.415037 */
    unsigned char skew[4] = { 'A', 'A', 'A', 'B' };
    approx("min_entropy(AAAB)=-log2(.75)", entroc_min_entropy(skew, 4),
           -log2(0.75), 1e-9);

    /* min-entropy <= shannon always */
    checks++;
    if (entroc_min_entropy(skew, 4) <= entroc_shannon(skew, 4) + 1e-9) {
        printf("PASS min_entropy<=shannon\n");
    } else { printf("FAIL min_entropy<=shannon\n"); failures++; }

    /* Chi-square: uniform 0..255 -> exactly 0 (every bucket == expected) */
    approx("chi_square(uniform)=0", entroc_chi_square(uniform, 256), 0.0, 1e-9);
    /* Skewed (all same byte) chi-square is large & positive */
    checks++;
    if (entroc_chi_square(zeros, 256) > 1000.0) {
        printf("PASS chi_square(all-zeros) large\n");
    } else { printf("FAIL chi_square(all-zeros) large\n"); failures++; }

    /* Classification */
    unsigned char hexbuf[64];
    const char *hs = "0123456789abcdef";
    for (int i = 0; i < 64; i++) hexbuf[i] = (unsigned char)hs[i % 16];
    eq_str("classify(hex)", class_name(entroc_classify(hexbuf, 64,
           entroc_shannon(hexbuf, 64))), "hex");

    const char *text = "The quick brown fox jumps over the lazy dog. Hello world, this is plain text.";
    size_t tl = strlen(text);
    eq_str("classify(text)", class_name(entroc_classify(
           (const unsigned char *)text, tl, entroc_shannon((const unsigned char*)text, tl))),
           "text");

    approx("shannon(empty)=0", entroc_shannon(zeros, 0), 0.0, 1e-9);

    /* Secret detection: PEM + AWS + JWT + long hex */
    const char *doc =
        "prefix AKIAIOSFODNN7EXAMPLE middle "
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N "
        "-----BEGIN CERTIFICATE-----\nMIIBkzCB/QIJAKj34GkxFhD9\n-----END CERTIFICATE-----\n"
        "sha=5d41402abc4b2a76b9719d911017c592 end";
    entroc_secret_t *sec = NULL;
    size_t sc = entroc_scan_secrets((const unsigned char *)doc, strlen(doc), &sec);
    checks++;
    if (sc >= 4) { printf("PASS scan_secrets count>=4 (got %zu)\n", sc); }
    else { printf("FAIL scan_secrets count>=4 (got %zu)\n", sc); failures++; }

    int saw_aws = 0, saw_jwt = 0, saw_pem = 0, saw_hex = 0;
    for (size_t i = 0; i < sc; i++) {
        if (strcmp(sec[i].kind, "aws-access-key-id") == 0) saw_aws = 1;
        if (strcmp(sec[i].kind, "jwt") == 0) saw_jwt = 1;
        if (strncmp(sec[i].kind, "pem", 3) == 0) saw_pem = 1;
        if (strncmp(sec[i].kind, "hex", 3) == 0) saw_hex = 1;
        /* preview must be redacted: never contain full 20-char AWS id */
        checks++;
        if (strstr(sec[i].preview, "[redacted]") != NULL) {
            /* ok */
        } else { printf("FAIL preview not redacted: %s\n", sec[i].preview); failures++; }
        checks--; /* fold into single reported check below */
    }
    eq_sz("saw aws", (size_t)saw_aws, 1);
    eq_sz("saw jwt", (size_t)saw_jwt, 1);
    eq_sz("saw pem", (size_t)saw_pem, 1);
    eq_sz("saw hex", (size_t)saw_hex, 1);

    /* previews never leak the full AWS key */
    for (size_t i = 0; i < sc; i++) {
        checks++;
        if (strstr(sec[i].preview, "AKIAIOSFODNN7EXAMPLE") != NULL) {
            printf("FAIL preview leaked full AWS key\n"); failures++;
        } else {
            printf("PASS preview redacted (%s)\n", sec[i].kind);
        }
    }
    free(sec);

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
