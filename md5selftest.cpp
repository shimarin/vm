// MD5 と MAC 導出自検
//
// netif.cpp に組み込まれた MD5 実装を、ビルド対象そのものから検証する。
// 実行には外部依存が要らないので `make test` でいつでも確認できる。
//
// 期待値は md5sum と Python hashlib が一致した値 (RFC 1321 のテストベクトルも含む)。
// `./md5selftest.bin --sweep` は長さ 0..1000 のダイジェストを "L<長さ> <hex>" で列挙する。
// pattern() と同じ生成式を下側のスクリプトに用意すれば、外部実装との突合に使える。

#include "netif.cpp"

#include <cstdio>
#include <cstring>
#include <string>

static std::string hexdigest(const std::string& s) {
    uint8_t d[16];
    netif::md5((const uint8_t*)s.data(), s.size(), d);
    char h[33];
    for (int i = 0; i < 16; i++) sprintf(h + i*2, "%02x", d[i]);
    h[32] = 0;
    return h;
}

// パディング境界を偏ったバイト列で通すための長さ依存パターン
static std::string pattern(size_t length) {
    std::string s;
    for (size_t i = 0; i < length; i++) s += (char)((i*7 + length*13) & 0xff);
    return s;
}

int main(int argc, char** argv) {
    static const struct { std::string in; const char* want; } vectors[] = {
        {"", "d41d8cd98f00b204e9800998ecf8427e"},
        {"a", "0cc175b9c0f1b6a831c399e269772661"},
        {"abc", "900150983cd24fb0d6963f7d28e17f72"},
        {"message digest", "f96b697d7cb7938d525a2f31aaf161d0"},
        {"The quick brown fox jumps over the lazy dog", "9e107d9d372bb6826bd81d3542a419d6"},
        {std::string(55, 'A'), "e38a93ffe074a99b3fed47dfbe37db21"},
        {std::string(56, 'B'), "ee0a6d91f573b47a98f7ce0b4d671c5f"},
        {std::string(63, 'C'), "50f27bb1fb90ec20f7248dc904d544cc"},
        {std::string(64, 'D'), "0889bbcdfc660e41589a50b83a9718e3"},
        {std::string(65, 'E'), "fa43f64620df1a542bb024fb378ab2a7"},
        {std::string(120, 'F'), "59f761506dfa597b0faf1968f7cca867"},
        {std::string("\x00\x01\x02\xff", 4), "0416dab819887333af831f8c765ac2ae"},
        // VM 名からの MAC 導出で実際に叩く入力
        {"fwcfg-test:0", "f4f71f0eed3aead87cd18f60b4a5a9e4"},
        {"gnome:0",      "0a5efdbf6bfb9008c8042d93e367792d"},
        {"test-vm:1",    "abe87a898968c048b6104885ae68b9b6"},
        {"vm1:0",        "f6d124b45f9932a13c0d42ae875e9647"},
        // 複数ブロックとパディング境界
        {pattern(119),  "def9fbe3a5e16d82789ed91833f9cb02"},
        {pattern(120),  "9bafdf32277ca087bf47e7a92a125b6a"},
        {pattern(127),  "6659b15fd850baa9d9ca0ddb27e81ac2"},
        {pattern(128),  "52cc29caecfd9380a2261a80c58e6787"},
        {pattern(129),  "f81a1b6781db102796231ae0d5824d4b"},
        {pattern(191),  "a19b00889e7124faf39f3921d4618f9c"},
        {pattern(192),  "ef204c6d4d11c8124b4f50a9c73d6cfc"},
        {pattern(199),  "69c7fbab5d0cb48fd8f75b540f197e26"},
        {pattern(200),  "0b4adde3d22fc8d8ccf8705fa1893149"},
        {pattern(255),  "dd4b3f0e69a7f311dfdf4f31eca40793"},
        {pattern(256),  "4335b1197cb589ecc218fd1ed8e39874"},
        {pattern(257),  "d6e4444b105d4011753c5df3c8ed8f7b"},
        {pattern(1000), "f8005195b42b4d79210e605abd0ddad1"},
    };

    static const struct { const char* vmname; int net_num; const char* want; } macs[] = {
        {"fwcfg-test", 0, "52:54:00:74:f7:1f"},
        {"gnome",      0, "52:54:00:0a:5e:fd"},
        {"test-vm",    1, "52:54:00:2b:e8:7a"},
        {"vm1",        0, "52:54:00:76:d1:24"},
    };

    int failed = 0;
    for (const auto& t : vectors) {
        auto got = hexdigest(t.in);
        if (got != t.want) {
            failed++;
            printf("FAIL digest len=%zu got=%s want=%s\n", t.in.size(), got.c_str(), t.want);
        }
    }
    for (const auto& t : macs) {
        auto got = netif::generate_macaddr_from_name(t.vmname, t.net_num);
        if (got != t.want) {
            failed++;
            printf("FAIL mac %s:%d got=%s want=%s\n", t.vmname, t.net_num, got.c_str(), t.want);
        }
    }

    if (argc > 1 && !strcmp(argv[1], "--sweep")) {
        for (size_t n = 0; n <= 1000; n++) printf("L%zu %s\n", n, hexdigest(pattern(n)).c_str());
    }

    if (failed) {
        printf("%d FAILED\n", failed);
        return 1;
    }
    printf("all %d digest vectors and %d mac vectors OK\n",
           (int)(sizeof vectors/sizeof vectors[0]), (int)(sizeof macs/sizeof macs[0]));
    return 0;
}
