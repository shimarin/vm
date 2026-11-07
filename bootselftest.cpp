// システムイメージからのブートファイル探索・展開の自己検
//
// system_image.cpp の find_boot_files() と metadata を、合成したディレクトリツリー
// 上で検証する。squashfs のイメージもマウントも要らないので `make test` でいつでも
// 確認できる (gunzip は vm の実行時依存そのまま)。
//
// カーネルの本体は合成したバイト列で、アーキテクチャはマジック番号だけで判定されて
// いる。EFI zboot のヘッダは drivers/firmware/efi/libstub/zboot.c の構成に合わせて
// いる (先頭 28 バイトがヘッダ、その後に gzip ストリームが続く)。

#include "system_image.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

// Everything this test makes - the image trees, and the host files that stand outside
// them - goes into one directory that this run made for itself.  Fixed names under
// /tmp would collide with a test running at the same time, and one that is already
// there, or is a link to something that is, would be overwritten and then removed.
// mkdtemp is exclusive and gives the directory a mode of 0700, so nothing of anyone
// else's is in it and nothing can put a file in it while we run.
static std::filesystem::path sandbox;

static void remove_sandbox()
{
    std::error_code ignored;
    std::filesystem::remove_all(sandbox, ignored); // ours, and only ours
}

static bool make_sandbox()
{
    auto pattern = (std::filesystem::temp_directory_path() / "vm-bootselftest-XXXXXX").string();
    std::vector<char> buffer(pattern.begin(), pattern.end());
    buffer.push_back('\0');
    if (mkdtemp(buffer.data()) == nullptr) return false;
    sandbox = buffer.data();
    return true;
}

static int failed = 0;

static void fail(const std::string& what)
{
    failed++;
    std::printf("FAIL %s\n", what.c_str());
}

// A read that is supposed to refuse instead of waiting gets a process of its own.  In
// this one, the only way out of a blocked open is a signal handler, and a handler may
// print nothing and may take the tree away from under the code that made it.  So the
// child arms its own alarm() - there is nothing to catch it, so it simply dies - and
// says what the read answered on a pipe, while this, the parent, waits for it, stops
// it if waiting is what it did instead, and reads whatever it managed to say.
struct guarded_read { bool blocked; std::string said; };

// The callable is not named read: this function reads from the pipe as well.
static guarded_read read_within(const std::function<std::string()>& attempt, int timeout_ms)
{
    int fds[2];
    if (pipe(fds) < 0) throw std::runtime_error("pipe() failed: " + std::string(strerror(errno)));

    auto pid = fork();
    if (pid < 0) {
        close(fds[0]); close(fds[1]);
        throw std::runtime_error("fork() failed: " + std::string(strerror(errno)));
    }

    if (pid == 0) {
        close(fds[0]);
        alarm(timeout_ms / 1000 + 1);
        auto said = attempt(); // write(2) is all this has to do afterwards, and it is safe
        auto ignored = write(fds[1], said.data(), said.size());
        (void) ignored;
        _exit(0);
    }

    close(fds[1]);

    int status = 0;
    for (int waited = 0; ; waited += 50) {
        if (waitpid(pid, &status, WNOHANG) == pid) break;
        if (waited <= timeout_ms + 500) { usleep(50 * 1000); continue; }
        // alarm() did not reach whatever the child is stuck in
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
        break;
    }

    std::string said;
    for (;;) {
        char buffer[512];
        auto got = read(fds[0], buffer, sizeof(buffer));
        if (got <= 0) break;
        said.append(buffer, got);
    }
    close(fds[0]);

    // alarm(), or the kill above, is the read having waited; any other signal is the
    // reader itself going wrong, which is worth telling apart from an answer.
    bool blocked = false;
    if (!WIFEXITED(status)) {
        auto signal = WTERMSIG(status);
        blocked = WIFSIGNALED(status) && (signal == SIGALRM || signal == SIGKILL);
        if (!blocked) said += " (the reader died on signal " + std::to_string(signal) + ")";
    }
    return {blocked, said};
}

static std::string show(const std::filesystem::path& value) {return value.string();}
static std::string show(const std::string& value) {return "\"" + value + "\"";}
template <typename T>
static std::string show(const std::optional<T>& value) {return value? show(*value) : std::string("(none)");}
// vsock の export は port:name の並びとして見比べる (source はメッセージの文面なので比較しない)
static std::string show(const std::vector<std::string>& values)
{
    std::string out;
    for (const auto& value : values) { if (!out.empty()) out += ","; out += value; }
    return "[" + out + "]";
}
static std::string show(unsigned value) {return std::to_string(value);}

template <typename T, typename U>
static void check(const std::string& what, const T& got, const U& want)
{
    if (got == want) return;
    //else
    fail(what + " got=" + show(got) + " want=" + show(want));
}

static void write_file(const std::filesystem::path& path, const std::string& content)
{
    std::filesystem::create_directories(path.parent_path());
    std::ofstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("cannot write " + path.string());
    file.write(content.data(), content.size());
    if (!file) throw std::runtime_error("cannot write " + path.string());
}

static std::string read_file(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    return std::string{std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

static std::vector<std::string> exports_as(const std::vector<system_image::vsock_export>& exports)
{
    std::vector<std::string> out;
    for (const auto& e : exports) out.push_back(std::to_string(e.port) + ":" + e.name);
    return out;
}

static std::vector<system_image::vsock_export> requested(const std::vector<std::string>& texts)
{
    std::vector<system_image::vsock_export> out;
    for (const auto& text : texts) out.push_back(system_image::parse_vsock_export("--export-vsock", text));
    return out;
}

static std::vector<system_image::vsock_export> declared(const std::vector<std::string>& texts)
{
    std::vector<system_image::vsock_export> out;
    for (const auto& text : texts) out.push_back(system_image::parse_vsock_export("/.genpack/vsock-exports", text));
    return out;
}

// マジック番号を置いた、合成したカーネルの本体
static std::string fake_kernel(size_t size = 8192)
{
    std::string kernel(size, '\0');
    for (size_t i = 0; i < size; i++) kernel[i] = static_cast<char>((i * 31 + 7) & 0xff);
    return kernel;
}

static std::string x86_kernel()
{
    auto kernel = fake_kernel();
    memcpy(&kernel[514], "HdrS", 4); // x86 の setup header の署名 (0x202)
    return kernel;
}

static std::string aarch64_kernel()
{
    auto kernel = fake_kernel();
    memcpy(&kernel[0x38], "ARMd", 4);
    return kernel;
}

static std::string riscv64_kernel()
{
    auto kernel = fake_kernel();
    memcpy(&kernel[0x30], "RISCV", 5);
    return kernel;
}

static std::string gzip_of(const std::filesystem::path& file)
{
    auto pipe = popen(("gzip -c -n " + file.string()).c_str(), "r");
    if (!pipe) throw std::runtime_error("popen() failed");
    std::string out;
    char buffer[4096];
    size_t size;
    while ((size = fread(buffer, 1, sizeof(buffer), pipe)) > 0) out.append(buffer, size);
    if (pclose(pipe) != 0) throw std::runtime_error("gzip failed");
    return out;
}

// EFI zboot image: ヘッダの後ろに gzip ストリームが続く
static std::string zboot_of(const std::string& gzip)
{
    std::string header(64, '\0');
    header[0] = 'M'; header[1] = 'Z';
    memcpy(&header[4], "zimg", 4);
    memcpy(&header[24], "gzip", 4);
    return header + gzip;
}

// boot/ を持つツリー。unpacked/ に展開されたファイルが現れる
struct fixture {
    std::filesystem::path root;
    std::filesystem::path unpack_dir;

    explicit fixture(const std::string& name)
        : root(sandbox / name)
        , unpack_dir(root / "unpacked")
    {
        std::filesystem::remove_all(root); // nothing of anyone else's can be here
    }
    ~fixture() { std::filesystem::remove_all(root); }

    // 展開の元になるカーネルを書いておく場所 (boot/ の探索対象にはならない名前)
    std::filesystem::path source(const std::string& name) {return root / "src" / name;}
    system_image::boot_files find() {return system_image::find_boot_files(root, unpack_dir);}
};

int main()
{
    if (!make_sandbox()) {
        std::printf("FAIL could not make a private directory to work in\n");
        return 1;
    }

    // boot/kernel と boot/initramfs (genpack の mkimage が置く名前)
    {
        fixture f("plain");
        write_file(f.root / "boot/kernel", x86_kernel());
        write_file(f.root / "boot/initramfs", "initramfs");
        auto boot = f.find();
        check("kernel", boot.kernel, f.root / "boot/kernel");
        check("initramfs", boot.initramfs, f.root / "boot/initramfs");
        check("arch", boot.arch, std::string("x86_64"));
    }

    // gzip されたカーネルは、展開したファイルを返す
    {
        fixture f("gzip");
        auto kernel = x86_kernel();
        write_file(f.source("vmlinux"), kernel);
        write_file(f.root / "boot/kernel", gzip_of(f.source("vmlinux")));
        write_file(f.root / "boot/initramfs.img", "initramfs");
        auto boot = f.find();
        if (boot.kernel == f.root / "boot/kernel") fail("the gzipped kernel is used as it is");
        check("unpacked kernel", read_file(boot.kernel), kernel);
        check("initramfs", boot.initramfs, f.root / "boot/initramfs.img");
        check("arch", boot.arch, std::string("x86_64"));
    }

    // EFI zboot image に包まれた gzip のカーネル
    {
        fixture f("zboot");
        auto kernel = x86_kernel();
        write_file(f.source("vmlinuz"), kernel);
        write_file(f.root / "boot/vmlinuz", zboot_of(gzip_of(f.source("vmlinuz"))));
        auto boot = f.find();
        if (boot.kernel == f.root / "boot/vmlinuz") fail("the zboot image is not unpacked");
        check("unpacked kernel", read_file(boot.kernel), kernel);
        check("initramfs", boot.initramfs, std::optional<std::filesystem::path>());
        check("arch", boot.arch, std::string("x86_64"));
    }

    // 配布ディストリビューションのカーネルパッケージが置く名前と、そのうち新しい方を選ぶ挙動
    {
        fixture f("versioned");
        write_file(f.root / "boot/kernel-1.0.0", fake_kernel());
        write_file(f.root / "boot/vmlinuz-2.0.0", aarch64_kernel());
        write_file(f.root / "boot/initrd.img-2.0.0", "initrd");
        std::filesystem::last_write_time(f.root / "boot/vmlinuz-2.0.0",
            std::filesystem::last_write_time(f.root / "boot/kernel-1.0.0") + std::chrono::seconds(60));
        auto boot = f.find();
        check("the latest kernel", boot.kernel, f.root / "boot/vmlinuz-2.0.0");
        check("the initrd of the same version", boot.initramfs, f.root / "boot/initrd.img-2.0.0");
        check("arch", boot.arch, std::string("aarch64"));
    }

    {
        fixture f("riscv");
        write_file(f.root / "boot/kernel-6.6.0", riscv64_kernel());
        write_file(f.root / "boot/initramfs-6.6.0.img", "initramfs");
        auto boot = f.find();
        check("kernel", boot.kernel, f.root / "boot/kernel-6.6.0");
        check("initramfs", boot.initramfs, f.root / "boot/initramfs-6.6.0.img");
        check("arch", boot.arch, std::string("riscv64"));
    }

    // boot/ もカーネルもないツリーは例外で
    {
        fixture f("no-boot");
        try {
            f.find();
            fail("a tree without boot/ is reported");
        } catch (const std::runtime_error&) {}
    }
    {
        fixture f("no-kernel");
        write_file(f.root / "boot/README", "no kernel here");
        try {
            f.find();
            fail("a boot directory without a kernel is reported");
        } catch (const std::runtime_error&) {}
    }

    // /.genpack/ の読み方: そのイメージに無いキーは std::nullopt
    {
        fixture f("metadata");
        write_file(f.root / ".genpack/artifact", "genpack\n");
        write_file(f.root / ".genpack/arch", "x86_64\n");
        write_file(f.root / ".genpack/timestamp.commit", "38e5511 1752279109 2025-07-12T00:11:49Z\n");
        auto meta = system_image::metadata{f.root};
        check("artifact", meta.artifact(), std::string("genpack"));
        check("arch", meta.arch(), std::string("x86_64"));
        check("timestamp.commit", meta.timestamp_commit(), std::string("38e5511 1752279109 2025-07-12T00:11:49Z"));
        check("variant of an image built without one", meta.variant(), std::optional<std::string>());
        check("a key genpack does not write", meta.get("nonexistent"), std::optional<std::string>());
        if (!meta.has("artifact") || meta.has("variant")) fail("has()");
    }
    {
        fixture f("no-metadata");
        auto meta = system_image::metadata{f.root};
        check("no /.genpack at all", meta.artifact(), std::optional<std::string>());
    }

    // /.genpack/vsock-exports: 1 行に 1 単位。コメントと空行は読み飛ばす
    // (同じ行が何度も現れても 1 つの宣言として扱うのはマージ側の仕事)
    {
        fixture f("vsock-exports");
        write_file(f.root / ".genpack/vsock-exports",
            "# ゲスト側が listen しているポート\n"
            "3080:librechat\n"
            "\n"
            "  80:http  \r\n"
            "3080:librechat\n");
        auto exports = system_image::declared_vsock_exports(system_image::metadata{f.root});
        check("declared exports", exports_as(exports), std::vector<std::string>{
            "3080:librechat", "80:http", "3080:librechat"});
        check("where it was declared", exports.front().source,
            std::string("/.genpack/vsock-exports 3080:librechat"));
    }
    {
        fixture f("no-vsock-exports");
        check("an image that declares nothing",
            exports_as(system_image::declared_vsock_exports(system_image::metadata{f.root})),
            std::vector<std::string>());
    }
    {
        fixture f("bad-vsock-exports");
        write_file(f.root / ".genpack/vsock-exports", "3080:librechat\n80:a bad name\n");
        try {
            system_image::declared_vsock_exports(system_image::metadata{f.root});
            fail("a line the image got wrong is reported");
        } catch (const std::runtime_error& e) {
            if (std::string(e.what()).find("/.genpack/vsock-exports") == std::string::npos)
                fail("the message names the file it came from: " + std::string(e.what()));
        }
    }

    // 無い宣言と、読めない宣言は違う。読めないものを「宣言なし」にして VM を起動すると、
    // 必要なソケットが一本も無いまま動き出す
    for (const std::string& kind : {"unreadable", "not-a-file", "no-dot-genpack-dir"}) {
        fixture f("declared-" + kind);
        if (kind == "unreadable") {
            write_file(f.root / ".genpack/vsock-exports", "3080:librechat\n");
            std::filesystem::permissions(f.root / ".genpack/vsock-exports", std::filesystem::perms::none);
        } else if (kind == "not-a-file") {
            std::filesystem::create_directories(f.root / ".genpack/vsock-exports");
        } else {
            write_file(f.root / ".genpack", "not a directory\n");
        }
        try {
            system_image::declared_vsock_exports(system_image::metadata{f.root});
            fail("a declaration that cannot be read (" + kind + ") is reported");
        } catch (const std::runtime_error& e) {
            // パスが出ていないと、どのイメージのどのファイルが読めないのか分からない
            if (std::string(e.what()).find("vsock-exports") == std::string::npos
                && std::string(e.what()).find(".genpack") == std::string::npos)
                fail("the message names the path for " + kind + ": " + std::string(e.what()));
        }
        if (kind == "no-dot-genpack-dir") std::filesystem::remove(f.root / ".genpack");
        else {
            std::filesystem::permissions(f.root / ".genpack", std::filesystem::perms::all);
            if (kind == "not-a-file") std::filesystem::remove_all(f.root / ".genpack/vsock-exports");
            else std::filesystem::permissions(f.root / ".genpack/vsock-exports", std::filesystem::perms::all);
        }
    }

    // シンボリックリンクは辿らない。イメージ内の名前はイメージが選んだものなので、
    // 辿ればホスト側のファイルを読み、その内容でホストにソケットを作ることになる
    for (const std::string& kind : {"in-tree", "outside", "dangling"}) {
        fixture f("link-" + kind);
        std::filesystem::create_directories(f.root / ".genpack");
        auto key = f.root / ".genpack/vsock-exports";
        if (kind == "in-tree") {
            write_file(f.root / ".genpack/other", "9999:evil\n");
            std::filesystem::create_symlink(f.root / ".genpack/other", key);
        } else if (kind == "outside") {
            // イメージの外（ホスト）に置いた宣言。リンクを辿ったら読めてしまう
            auto outside = sandbox / ("host-" + kind);
            write_file(outside, "9999:evil\n");
            std::filesystem::create_symlink(outside, key);
        } else {
            std::filesystem::create_symlink(f.root / ".genpack/gone", key);
        }
        try {
            auto exports = system_image::declared_vsock_exports(system_image::metadata{f.root});
            fail("a declaration behind a symlink (" + kind + ") is used: " + show(exports_as(exports)));
        } catch (const std::runtime_error& e) {
            if (std::string(e.what()).find("symbolic link") == std::string::npos)
                fail("the symlink (" + kind + ") is reported as such: " + std::string(e.what()));
        }
        std::filesystem::remove(sandbox / ("host-" + kind));
    }
    {
        // /.genpack 自体がリンクなのも辿らない
        fixture f("link-dot-genpack");
        write_file(f.root / "elsewhere/.genpack-inner/vsock-exports", "9999:evil\n");
        std::filesystem::create_symlink(f.root / "elsewhere/.genpack-inner", f.root / ".genpack");
        try {
            auto exports = system_image::declared_vsock_exports(system_image::metadata{f.root});
            fail("a /.genpack behind a symlink is used: " + show(exports_as(exports)));
        } catch (const std::runtime_error& e) {
            if (std::string(e.what()).find("symbolic link") == std::string::npos
                && std::string(e.what()).find("directory") == std::string::npos)
                fail("the /.genpack symlink is reported: " + std::string(e.what()));
        }
    }
    {
        // 書き手のいない FIFO は open が復帰しないので、判定にたどり着かずに vm が止まる。
        // 待つことを検査するために待つ訳にいかないので、読ませるのは別プロセス
        fixture f("fifo-vsock-exports");
        std::filesystem::create_directories(f.root / ".genpack");
        mkfifo((f.root / ".genpack/vsock-exports").c_str(), 0600);
        auto seen = read_within([&f] {
            try {
                auto exports = system_image::declared_vsock_exports(system_image::metadata{f.root});
                return std::string("read ") + std::to_string(exports.size()) + " declarations";
            } catch (const std::runtime_error& e) {
                return std::string(e.what());
            }
        }, 2000);
        if (seen.blocked) fail("a FIFO where the declaration should be is reported");
        else if (seen.said.find("not a regular file") == std::string::npos)
            fail("the FIFO is reported as such, not as: " + seen.said);
    }
    // get() は読み取り失敗を「そのキーは無い」と同じに扱うが、リンクは辿らない
    {
        fixture f("get-behind-a-link");
        std::filesystem::create_directories(f.root / ".genpack");
        auto outside = sandbox / "host-artifact";
        write_file(outside, "from-the-host\n");
        std::filesystem::create_symlink(outside, f.root / ".genpack/artifact");
        auto meta = system_image::metadata{f.root};
        check("an /.genpack key behind a link reads as absent", meta.artifact(), std::optional<std::string>());
        std::filesystem::remove(outside);
    }

    // PORT[:NAME] は --export-vsock と /.genpack/vsock-exports の共通の書式
    {
        auto e = system_image::parse_vsock_export("--export-vsock", "80");
        check("port", e.port, (uint32_t)80);
        check("NAME defaults to the port", e.name, std::string("80"));
        check("what asked for it", e.source, std::string("--export-vsock 80"));
        for (const std::string& bad : {"0", "4294967295:x", "80:a/b", "80:", "http"}) {
            try {
                system_image::parse_vsock_export("--export-vsock", bad);
                fail("rejects " + bad);
            } catch (const std::runtime_error&) {}
        }
    }

    // イメージの宣言とコマンドラインを合わせる
    {
        std::vector<std::string> notices;
        auto merged = system_image::merge_vsock_exports(requested({"3080:web"}),
            declared({"3080:librechat", "80:http", "3080:librechat"}), notices);
        check("the command line wins for a port it mentions", exports_as(merged),
            std::vector<std::string>{"3080:web", "80:http"});
        if (notices.size() != 1 || notices.front().find("overridden") == std::string::npos)
            fail("the override is reported once, as " + show(notices));
    }
    {
        std::vector<std::string> notices;
        auto merged = system_image::merge_vsock_exports(requested({"3080:librechat"}),
            declared({"3080:librechat", "3080:librechat"}), notices);
        check("an export asked for twice is exported once", exports_as(merged),
            std::vector<std::string>{"3080:librechat"});
        if (!notices.empty()) fail("nothing to say when the image asks for what was asked for, as " + show(notices));
    }
    {
        std::vector<std::string> notices;
        auto merged = system_image::merge_vsock_exports(std::vector<system_image::vsock_export>(),
            declared({"80:http", "80:http", "90:api"}), notices);
        check("a line repeated in the file is one export", exports_as(merged),
            std::vector<std::string>{"80:http", "90:api"});
        if (!notices.empty()) fail("a repeated line needs no notice, as " + show(notices));
    }
    {
        std::vector<std::string> notices;
        try {
            system_image::merge_vsock_exports(std::vector<system_image::vsock_export>(),
                declared({"80:http", "80:api"}), notices);
            fail("two names exported for one port is reported");
        } catch (const std::runtime_error&) {}
        try {
            system_image::merge_vsock_exports(std::vector<system_image::vsock_export>(),
                declared({"80:http", "90:http"}), notices);
            fail("one name exported for two ports is reported");
        } catch (const std::runtime_error&) {}
    }

    // --export-vsock 同士の重複は、イメージを読む前に通す。--bios もこの経路なので
    // 検査もその手前にある
    {
        system_image::check_vsock_exports(requested({"80:http", "90:api"}));
        try {
            system_image::check_vsock_exports(requested({"80:http", "80:api"}));
            fail("one port named twice on the command line is refused");
        } catch (const std::runtime_error& e) {
            if (std::string(e.what()).find("80") == std::string::npos)
                fail("the message names the port: " + std::string(e.what()));
        }
        try {
            system_image::check_vsock_exports(requested({"80:http", "90:http"}));
            fail("one name used for two ports on the command line is refused");
        } catch (const std::runtime_error&) {}
    }

    // コマンドラインが名指ししたポートは、イメージがそのポートに複数の名前を置いていても
    // まとめて覆う。上書きされた宣言はそれぞれ報告される
    {
        std::vector<std::string> notices;
        auto merged = system_image::merge_vsock_exports(requested({"80:http"}),
            declared({"80:api", "80:web", "90:api"}), notices);
        check("the command line covers every name the image has for the port", exports_as(merged),
            std::vector<std::string>{"80:http", "90:api"});
        if (notices.size() != 2) fail("both overridden declarations are reported, as " + show(notices));
    }

    remove_sandbox();

    if (failed) {
        std::printf("%d FAILED\n", failed);
        return 1;
    }
    std::printf("boot file discovery and image metadata OK\n");
    return 0;
}
