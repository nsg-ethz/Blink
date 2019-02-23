#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>

#define ROT32(x, y) ((x << y) | (x >> (32 - y))) // avoid effort
uint32_t murmur3(const char *key, uint32_t len, uint32_t seed) {
	static const uint32_t c1 = 0xcc9e2d51;
	static const uint32_t c2 = 0x1b873593;
	static const uint32_t r1 = 15;
	static const uint32_t r2 = 13;
	static const uint32_t m = 5;
	static const uint32_t n = 0xe6546b64;
    //printf("seed: %u\n", seed);
    //printf("len: %u\n", len);
    //printf("key1: %hhd key2: %hhd\n", key[0], key[1]);


	uint32_t hash = seed;

	const int nblocks = len / 4;
	const uint32_t *blocks = (const uint32_t *) key;
	int i;
	uint32_t k;
	for (i = 0; i < nblocks; i++) {
		k = blocks[i];
		k *= c1;
		k = ROT32(k, r1);
		k *= c2;

		hash ^= k;
		hash = ROT32(hash, r2) * m + n;
	}

	const uint8_t *tail = (const uint8_t *) (key + nblocks * 4);
	uint32_t k1 = 0;

	switch (len & 3) {
		case 3:
			k1 ^= tail[2] << 16;
		case 2:
			k1 ^= tail[1] << 8;
		case 1:
			k1 ^= tail[0];

			k1 *= c1;
			k1 = ROT32(k1, r1);
			k1 *= c2;
			hash ^= k1;
	}

	hash ^= len;
	hash ^= (hash >> 16);
	hash *= 0x85ebca6b;
	hash ^= (hash >> 13);
	hash *= 0xc2b2ae35;
	hash ^= (hash >> 16);

	return hash;
}

int main(int argc, char **argv)
{
    uint16_t key = htons(10000);

    uint32_t hash = murmur3((char *)&key, 2, 2)%25;
    printf ("hash: %u\n", hash);
}

/*int main(int argc, char **argv)
{
    char *key = "thomas";
    printf ("key: %s\n", key);

    uint32_t seed = 11;
    uint32_t len = strlen(key);

    for (int i=0; i<100; i++)
    {
        uint32_t hash = murmur3_32(key, len, seed);
        printf ("hash: %u\n", hash);
        seed += 1;
    }
}*/
