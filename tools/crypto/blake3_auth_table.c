/*
 * Bounded Authenticator precomputation.
 *
 * Builds a direct-rank table of the first N bytes of
 * BLAKE3(password || "HANDSHAKE_FROM_SERVER" || challenge) for one finite
 * lexicographic password shard.  The raw table contains only prefixes; the
 * Python solver rechecks every hit with the full digest before responding.
 * Compile in the disposable competition workspace, for example:
 *   cc -O3 -fopenmp blake3_auth_table.c -o blake3_auth_table
 */

#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef _OPENMP
#include <omp.h>
#endif

static const uint32_t IV[8] = {
    0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU,
    0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U,
};
static const uint8_t PERM[16] = {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8};
static const char ALPHABET[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const uint8_t LABEL[] = "HANDSHAKE_FROM_SERVER";
static const uint8_t CHALLENGE[] = "CHALLENGE_CLIENT";
static const size_t LABEL_LEN = sizeof(LABEL) - 1;
static const size_t CHALLENGE_LEN = sizeof(CHALLENGE) - 1;

static uint32_t rotr32(uint32_t x, unsigned n) { return (x >> n) | (x << (32U - n)); }

static void g(uint32_t v[16], int a, int b, int c, int d, uint32_t x, uint32_t y) {
    v[a] += v[b] + x;
    v[d] = rotr32(v[d] ^ v[a], 16);
    v[c] += v[d];
    v[b] = rotr32(v[b] ^ v[c], 12);
    v[a] += v[b] + y;
    v[d] = rotr32(v[d] ^ v[a], 8);
    v[c] += v[d];
    v[b] = rotr32(v[b] ^ v[c], 7);
}

static void compress_block(uint32_t out[16], const uint32_t cv[8], const uint32_t block[16], uint32_t block_len, uint32_t flags) {
    uint32_t v[16];
    uint32_t schedule[16];
    for (int i = 0; i < 8; ++i) v[i] = cv[i];
    for (int i = 0; i < 4; ++i) v[8 + i] = IV[i];
    v[12] = 0;
    v[13] = 0;
    v[14] = block_len;
    v[15] = flags;
    for (int i = 0; i < 16; ++i) schedule[i] = (uint32_t)i;
    for (int round = 0; round < 7; ++round) {
        uint32_t m[16];
        for (int i = 0; i < 16; ++i) m[i] = block[schedule[i]];
        g(v, 0, 4, 8, 12, m[0], m[1]);
        g(v, 1, 5, 9, 13, m[2], m[3]);
        g(v, 2, 6, 10, 14, m[4], m[5]);
        g(v, 3, 7, 11, 15, m[6], m[7]);
        g(v, 0, 5, 10, 15, m[8], m[9]);
        g(v, 1, 6, 11, 12, m[10], m[11]);
        g(v, 2, 7, 8, 13, m[12], m[13]);
        g(v, 3, 4, 9, 14, m[14], m[15]);
        uint32_t next[16];
        for (int i = 0; i < 16; ++i) next[i] = schedule[PERM[i]];
        memcpy(schedule, next, sizeof(schedule));
    }
    for (int i = 0; i < 8; ++i) out[i] = v[i] ^ v[i + 8];
    for (int i = 0; i < 8; ++i) out[i + 8] = v[i + 8] ^ cv[i];
}

static void hash_password(const uint8_t password[6], uint8_t digest[32]) {
    uint8_t input[64] = {0};
    uint32_t block[16] = {0};
    for (int i = 0; i < 6; ++i) input[i] = (uint8_t)ALPHABET[password[i]];
    memcpy(input + 6, LABEL, LABEL_LEN);
    memcpy(input + 6 + LABEL_LEN, CHALLENGE, CHALLENGE_LEN);
    for (int i = 0; i < 16; ++i) {
        block[i] = ((uint32_t)input[4 * i]) |
                   ((uint32_t)input[4 * i + 1] << 8) |
                   ((uint32_t)input[4 * i + 2] << 16) |
                   ((uint32_t)input[4 * i + 3] << 24);
    }
    uint32_t out[16];
    compress_block(out, IV, block, (uint32_t)(6 + LABEL_LEN + CHALLENGE_LEN), 1U | 2U | 8U);
    for (int i = 0; i < 8; ++i) {
        digest[4 * i] = (uint8_t)out[i];
        digest[4 * i + 1] = (uint8_t)(out[i] >> 8);
        digest[4 * i + 2] = (uint8_t)(out[i] >> 16);
        digest[4 * i + 3] = (uint8_t)(out[i] >> 24);
    }
}

static uint64_t factorial_ratio(int n, int k) {
    uint64_t value = 1;
    for (int i = 0; i < k; ++i) value *= (uint64_t)(n - i);
    return value;
}

static uint64_t total_passwords(void) { return factorial_ratio(62, 6); }

static void unrank(uint64_t rank, uint8_t password[6]) {
    uint8_t remaining[62];
    for (int i = 0; i < 62; ++i) remaining[i] = (uint8_t)i;
    int remaining_len = 62;
    for (int pos = 0; pos < 6; ++pos) {
        uint64_t block = factorial_ratio(remaining_len - 1, 5 - pos);
        uint64_t index = rank / block;
        rank %= block;
        password[pos] = remaining[index];
        for (int j = (int)index; j + 1 < remaining_len; ++j) remaining[j] = remaining[j + 1];
        --remaining_len;
    }
}

/* Advance one lexicographic k-permutation of 0..61. */
static int next_permutation(uint8_t p[6]) {
    for (int pos = 5; pos >= 0; --pos) {
        uint8_t used[62] = {0};
        for (int i = 0; i < pos; ++i) used[p[i]] = 1;
        for (int candidate = (int)p[pos] + 1; candidate < 62; ++candidate) {
            if (used[candidate]) continue;
            p[pos] = (uint8_t)candidate;
            used[candidate] = 1;
            int next = 0;
            for (int j = pos + 1; j < 6; ++j) {
                while (used[next]) ++next;
                p[j] = (uint8_t)next;
                used[next] = 1;
            }
            return 1;
        }
    }
    return 0;
}

static void usage(const char *name) {
    fprintf(stderr, "usage: %s shard_index shard_count prefix_bytes output [limit]\n", name);
    fprintf(stderr, "challenge is fixed to the 16-byte CHALLENGE_CLIENT string\n");
}

int main(int argc, char **argv) {
    if (argc < 5 || argc > 6) {
        usage(argv[0]);
        return 2;
    }
    uint64_t shard_index = strtoull(argv[1], NULL, 10);
    uint64_t shard_count = strtoull(argv[2], NULL, 10);
    int prefix_bytes = atoi(argv[3]);
    const char *path = argv[4];
    if (shard_count == 0 || shard_index >= shard_count || prefix_bytes < 1 || prefix_bytes > 4) {
        fprintf(stderr, "invalid shard or prefix\n");
        return 2;
    }
    uint64_t total = total_passwords();
    uint64_t start = (total * shard_index) / shard_count;
    uint64_t stop = (total * (shard_index + 1)) / shard_count;
    if (argc == 6) {
        uint64_t limit = strtoull(argv[5], NULL, 10);
        if (limit < stop - start) stop = start + limit;
    }
    uint64_t count = stop - start;
    if (count == 0) {
        fprintf(stderr, "empty shard\n");
        return 2;
    }
    if (count > (uint64_t)SIZE_MAX / (uint64_t)prefix_bytes) {
        fprintf(stderr, "table size overflow\n");
        return 2;
    }
    size_t table_size = (size_t)(count * (uint64_t)prefix_bytes);
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0 || ftruncate(fd, (off_t)table_size) != 0) {
        fprintf(stderr, "cannot allocate table %s: %s\n", path, strerror(errno));
        if (fd >= 0) close(fd);
        return 1;
    }
    uint8_t *table = mmap(NULL, table_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (table == MAP_FAILED) {
        fprintf(stderr, "mmap failed: %s\n", strerror(errno));
        close(fd);
        return 1;
    }
    int workers = 1;
#ifdef _OPENMP
    workers = omp_get_max_threads();
#endif
#pragma omp parallel
    {
        int tid = 0;
        int nworkers = 1;
#ifdef _OPENMP
        tid = omp_get_thread_num();
        nworkers = omp_get_num_threads();
#endif
        uint64_t local_start = start + (count * (uint64_t)tid) / (uint64_t)nworkers;
        uint64_t local_stop = start + (count * (uint64_t)(tid + 1)) / (uint64_t)nworkers;
        uint8_t password[6];
        uint8_t digest[32];
        unrank(local_start, password);
        for (uint64_t rank = local_start; rank < local_stop; ++rank) {
            hash_password(password, digest);
            memcpy(table + (size_t)((rank - start) * (uint64_t)prefix_bytes), digest, (size_t)prefix_bytes);
            if (rank + 1 < local_stop) next_permutation(password);
        }
    }
    (void)workers;
    if (msync(table, table_size, MS_SYNC) != 0) fprintf(stderr, "warning: msync failed: %s\n", strerror(errno));
    munmap(table, table_size);
    close(fd);
    fprintf(stderr, "wrote %zu bytes for ranks [%" PRIu64 ",%" PRIu64 ")\n", table_size, start, stop);
    return 0;
}
