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
#include <cstring>
#include <fstream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>

static int failed = 0;

static void fail(const std::string& what)
{
    failed++;
    std::printf("FAIL %s\n", what.c_str());
}

static std::string show(const std::filesystem::path& value) {return value.string();}
static std::string show(const std::string& value) {return "\"" + value + "\"";}
template <typename T>
static std::string show(const std::optional<T>& value) {return value? show(*value) : std::string("(none)");}

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
        : root(std::filesystem::temp_directory_path() / ("vm-bootselftest-" + name))
        , unpack_dir(root / "unpacked")
    {
        std::filesystem::remove_all(root);
    }
    ~fixture() { std::filesystem::remove_all(root); }

    // 展開の元になるカーネルを書いておく場所 (boot/ の探索対象にはならない名前)
    std::filesystem::path source(const std::string& name) {return root / "src" / name;}
    system_image::boot_files find() {return system_image::find_boot_files(root, unpack_dir);}
};

int main()
{
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

    if (failed) {
        std::printf("%d FAILED\n", failed);
        return 1;
    }
    std::printf("boot file discovery and image metadata OK\n");
    return 0;
}
