/* cryptolite — 정답셋 코퍼스 소스 1 (docs/EVAL-SPEC.md §2)
 *
 * 이 파일의 목적은 **정답이 있는 리버싱 대상**을 만드는 것이다. 함수 이름이 곧
 * 정답이므로, 리버서가 의사코드만 보고 이름을 맞힐 수 있을 만큼 각 함수가
 * 특징적이어야 한다 — 그렇지 않으면 명명 정확도가 재는 것이 시스템 성능이 아니라
 * 문제의 모호함이 된다.
 *
 * 전부 순수 계산이다. 파일·레지스트리·네트워크를 건드리지 않는다 — 코퍼스는
 * 컴파일 대상일 뿐이고 어떤 경우에도 실행되지 않는다 (§10).
 *
 * 컴파일러가 인라인해 버리면 정답 함수가 사라지므로 `NOINLINE` 을 붙인다.
 * -O2/-O3 셀에서 함수가 통째로 없어지면 그 셀의 n 이 조용히 줄어든다.
 */

#include <stdio.h>
#include <string.h>

#if defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif

/* RC4 키 스케줄. S-box 256 바이트 초기화 + KSA 치환이 지문이다. */
NOINLINE void rc4_init(unsigned char *state, const unsigned char *key, int keylen) {
    int i, j = 0;
    for (i = 0; i < 256; i++) {
        state[i] = (unsigned char)i;
    }
    for (i = 0; i < 256; i++) {
        unsigned char tmp;
        j = (j + state[i] + key[i % keylen]) & 0xFF;
        tmp = state[i];
        state[i] = state[j];
        state[j] = tmp;
    }
}

/* RC4 스트림 생성 + XOR. 암복호가 같은 연산이라는 것이 특징이다. */
NOINLINE void rc4_crypt(unsigned char *state, unsigned char *buf, int len) {
    int i = 0, j = 0, n;
    for (n = 0; n < len; n++) {
        unsigned char tmp;
        i = (i + 1) & 0xFF;
        j = (j + state[i]) & 0xFF;
        tmp = state[i];
        state[i] = state[j];
        state[j] = tmp;
        buf[n] ^= state[(state[i] + state[j]) & 0xFF];
    }
}

/* 단일 바이트 XOR. 가장 흔한 난독화이고 RC4 와 혼동되기 쉬운 대상이다. */
NOINLINE void xor_decode(unsigned char *buf, int len, unsigned char key) {
    int i;
    for (i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

/* FNV-1a. 상수 0x811C9DC5 / 0x01000193 이 거의 고유 식별자다 (§5). */
NOINLINE unsigned int fnv1a_hash(const char *data, int len) {
    unsigned int hash = 0x811C9DC5u;
    int i;
    for (i = 0; i < len; i++) {
        hash ^= (unsigned char)data[i];
        hash *= 0x01000193u;
    }
    return hash;
}

/* djb2. 상수 5381 과 hash*33 형태가 지문이다. */
NOINLINE unsigned int djb2_hash(const char *str) {
    unsigned int hash = 5381u;
    const unsigned char *p = (const unsigned char *)str;
    while (*p) {
        hash = ((hash << 5) + hash) + *p++;
    }
    return hash;
}

static const char kBase64Alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Base64 인코딩. 알파벳 문자열과 3→4 바이트 확장이 지문이다. */
NOINLINE int base64_encode(const unsigned char *in, int len, char *out) {
    int i = 0, o = 0;
    while (i + 2 < len) {
        unsigned int v = ((unsigned int)in[i] << 16) | ((unsigned int)in[i + 1] << 8) | in[i + 2];
        out[o++] = kBase64Alphabet[(v >> 18) & 0x3F];
        out[o++] = kBase64Alphabet[(v >> 12) & 0x3F];
        out[o++] = kBase64Alphabet[(v >> 6) & 0x3F];
        out[o++] = kBase64Alphabet[v & 0x3F];
        i += 3;
    }
    if (i < len) {
        unsigned int v = (unsigned int)in[i] << 16;
        int rem = len - i;
        if (rem == 2) {
            v |= (unsigned int)in[i + 1] << 8;
        }
        out[o++] = kBase64Alphabet[(v >> 18) & 0x3F];
        out[o++] = kBase64Alphabet[(v >> 12) & 0x3F];
        out[o++] = (rem == 2) ? kBase64Alphabet[(v >> 6) & 0x3F] : '=';
        out[o++] = '=';
    }
    out[o] = '\0';
    return o;
}

/* 단순 가산 체크섬. xor_decode 와 헷갈리기 쉬운 루프 형태를 일부러 넣었다. */
NOINLINE unsigned int checksum_buffer(const unsigned char *buf, int len) {
    unsigned int sum = 0;
    int i;
    for (i = 0; i < len; i++) {
        sum += buf[i];
        sum = (sum << 3) | (sum >> 29);
    }
    return sum;
}

/* 여러 단계를 엮는 상위 함수. 콜그래프 위치 신호의 대상이다. */
NOINLINE int decode_config_blob(unsigned char *blob, int len, char *out) {
    unsigned char state[256];
    static const unsigned char key[] = {0x13, 0x37, 0xC0, 0xDE};
    xor_decode(blob, len, 0x5A);
    rc4_init(state, key, (int)sizeof(key));
    rc4_crypt(state, blob, len);
    return base64_encode(blob, len, out);
}

int main(void) {
    unsigned char blob[32];
    char out[64];
    int i;
    for (i = 0; i < (int)sizeof(blob); i++) {
        blob[i] = (unsigned char)(i * 7 + 3);
    }
    printf("%d %u %u %u\n", decode_config_blob(blob, (int)sizeof(blob), out),
           fnv1a_hash(out, (int)strlen(out)), djb2_hash(out),
           checksum_buffer(blob, (int)sizeof(blob)));
    return 0;
}
