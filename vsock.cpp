#include "vsock.h"
#include <array>
#include <vector>
#include <stdexcept>
#include <string>
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <dirent.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

class SHA256 {
private:
    static constexpr std::array<uint32_t, 64> K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    static constexpr std::array<uint32_t, 8> H0 = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    static uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }

    static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    static uint32_t sigma0(uint32_t x) {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }

    static uint32_t sigma1(uint32_t x) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }

    static uint32_t gamma0(uint32_t x) {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }

    static uint32_t gamma1(uint32_t x) {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }

public:
    static std::array<uint8_t, 32> hash(const std::string& input) {
        // 初期化
        std::array<uint32_t, 8> h = H0;
        std::vector<uint8_t> data(input.begin(), input.end());

        // パディング（FIPS 180-4）
        uint64_t bit_len = input.length() * 8;
        data.push_back(0x80);
        while ((data.size() % 64) != 56) {
            data.push_back(0x00);
        }
        for (int i = 7; i >= 0; --i) {
            data.push_back(static_cast<uint8_t>(bit_len >> (i * 8)));
        }

        // ブロック処理
        for (size_t i = 0; i < data.size(); i += 64) {
            std::array<uint32_t, 64> w;
            for (size_t j = 0; j < 16; ++j) {
                w[j] = (data[i + j*4] << 24) | (data[i + j*4 + 1] << 16) |
                       (data[i + j*4 + 2] << 8) | data[i + j*4 + 3];
            }
            for (size_t j = 16; j < 64; ++j) {
                w[j] = gamma1(w[j-2]) + w[j-7] + gamma0(w[j-15]) + w[j-16];
            }

            uint32_t a = h[0], b = h[1], c = h[2], d = h[3],
                     e = h[4], f = h[5], g = h[6], h_val = h[7];

            for (size_t j = 0; j < 64; ++j) {
                uint32_t t1 = h_val + sigma1(e) + ch(e, f, g) + K[j] + w[j];
                uint32_t t2 = sigma0(a) + maj(a, b, c);
                h_val = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }

            h[0] += a; h[1] += b; h[2] += c; h[3] += d;
            h[4] += e; h[5] += f; h[6] += g; h[7] += h_val;
        }

        // 結果をバイト列に変換
        std::array<uint8_t, 32> result;
        for (size_t i = 0; i < 8; ++i) {
            result[i*4] = h[i] >> 24;
            result[i*4 + 1] = (h[i] >> 16) & 0xFF;
            result[i*4 + 2] = (h[i] >> 8) & 0xFF;
            result[i*4 + 3] = h[i] & 0xFF;
        }
        return result;
    }
};

namespace vsock {
    namespace {
        // Block SIGCHLD while a proxy is being created, so that a proxy which dies
        // immediately cannot lose its notification before run_qemu() sets up its
        // signalfd. The previous mask is handed back so that the proxy (and QEMU)
        // can be execed without the block.
        void block_sigchld(sigset_t& previous)
        {
            sigset_t mask;
            sigemptyset(&mask);
            sigaddset(&mask, SIGCHLD);
            if (sigprocmask(SIG_BLOCK, &mask, &previous) != 0) throw std::runtime_error(std::string("sigprocmask() failed: ") + strerror(errno));
        }

        // Drop the descriptors inherited from the vm process. The VM lock fd in
        // particular must not survive: an orphaned proxy would otherwise keep the
        // name locked and make the VM look like it is still running.
        void close_inherited_fds(int keep)
        {
            std::vector<int> fds;
            if (auto dir = opendir("/proc/self/fd")) {
                while (auto entry = readdir(dir)) {
                    auto fd = atoi(entry->d_name);
                    if (fd > STDERR_FILENO && fd != keep) fds.push_back(fd);
                }
                closedir(dir);
            }
            for (auto fd : fds) close(fd);
        }

        // Start a proxy process (socat). The child refuses to outlive the vm
        // process and hands the exec result back through a close-on-exec pipe:
        // a successful exec closes the write end and the parent reads EOF, while
        // a failed exec delivers the errno.
        pid_t run_proxy(const char* chdir_to, const std::vector<std::string>& args)
        {
            sigset_t previous_mask;
            block_sigchld(previous_mask); // before fork(): a proxy that dies immediately must not slip through

            int handshake[2];
            if (pipe2(handshake, O_CLOEXEC) < 0) {
                sigprocmask(SIG_SETMASK, &previous_mask, nullptr);
                throw std::runtime_error(std::string("pipe2() failed: ") + strerror(errno));
            }

            auto parent = getpid();
            auto pid = fork();
            if (pid < 0) {
                close(handshake[0]); close(handshake[1]);
                sigprocmask(SIG_SETMASK, &previous_mask, nullptr);
                throw std::runtime_error("fork() failed");
            }
            if (pid == 0) {
                auto die = [&](int err) {
                    ssize_t w = write(handshake[1], &err, sizeof(err));
                    (void)w;
                    _exit(127);
                };
                close(handshake[0]);
                if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0) die(errno);
                if (getppid() != parent) die(ESHUTDOWN); // the parent died before prctl() took effect
                sigdelset(&previous_mask, SIGCHLD); // the block is ours to hold, not socat's to inherit
                sigprocmask(SIG_SETMASK, &previous_mask, nullptr);
                if (chdir_to && chdir(chdir_to) != 0) die(errno);
                close_inherited_fds(handshake[1]);
                std::vector<char*> argv;
                for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
                argv.push_back(nullptr);
                execvp(argv[0], argv.data());
                die(errno);
            }

            close(handshake[1]);
            auto err = 0;
            auto r = read(handshake[0], &err, sizeof(err)); // blocks until exec succeeds (EOF) or the child reports
            close(handshake[0]);
            if (r != 0) {
                waitpid(pid, nullptr, 0);
                throw std::runtime_error(std::string("Failed to start ") + args.front() + ": "
                    + (r == sizeof(err)? strerror(err) : "the process terminated immediately"));
            }
            return pid;
        }
    } // namespace

    pid_t run_sock_forward(uint32_t vsock_port, const std::filesystem::path& unix_sock_path)
    {
        return run_proxy(nullptr, {
            "socat",
            "VSOCK-LISTEN:" + std::to_string(vsock_port) + ",fork,reuseaddr",
            "UNIX-CONNECT:" + unix_sock_path.string()
        });
    }

    // The socket is created relative to dir (which the child chdir()s to) so that
    // long or oddly-named run directories cannot overflow sun_path or confuse
    // socat's address parser.
    pid_t run_vsock_export(uint32_t guest_cid, uint32_t vsock_port, const std::filesystem::path& dir, const std::string& socket_name)
    {
        return run_proxy(dir.c_str(), {
            "socat",
            "UNIX-LISTEN:" + socket_name + ",fork",
            "VSOCK-CONNECT:" + std::to_string(guest_cid) + ":" + std::to_string(vsock_port)
        });
    }

    uint32_t determine_guest_cid(uid_t uid, const std::string& vmname) {
        if (vmname.empty()) {
            throw std::invalid_argument("VM name cannot be empty");
        }
        auto hash = SHA256::hash(std::to_string(uid) + ":" + vmname);
        // 最初の4バイトをuint32_tに変換
        uint32_t hash_value = (hash[0] << 24) | (hash[1] << 16) | (hash[2] << 8) | hash[3];
        // CID範囲（3〜4294967295）にマッピング
        return (hash_value % 4294967293) + 3;
    }

}