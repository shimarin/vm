#include <iostream>
#include <fstream>
#include <filesystem>
#include <optional>
#include <vector>
#include <cassert>
#include <future>
#include <set>
//#include <format>

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <termios.h>
#include <pwd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <sys/file.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <linux/fs.h>
#include <ext2fs/ext2_fs.h>
#include <linux/cryptouser.h>
#include <linux/if_alg.h>

#include <libsmartcols/libsmartcols.h>
#include <systemd/sd-daemon.h>
#include <argparse/argparse.hpp>
#include <iniparser/iniparser.h>
extern "C" {
#include <squashfuse/squashfuse.h>
}

#include "run_dir.h"
#include "json_messaging.h"
#include "netif.h"
#include "pci.h"
#include "usb.h"
#include "vsock.h"

static const uint32_t default_memory_size = 2048;

template <typename T>
class Finally {
    std::function<void(const T&)> func;
    const T& arg;
public:
    Finally(std::function<void(const T&)> _func, const T& _arg) : func(_func), arg(_arg) {}
    ~Finally() { func(arg); }
};

static void MD5(const uint8_t* data, size_t length, uint8_t result[16])
{
    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type = "hash",
        .salg_name = "md5"
    };
    
    int tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (tfmfd == -1) throw std::runtime_error("MD5: socket() failed");
    //else
    Finally<int> tfmfd_cleanup([](auto fd){
        close(fd);
    }, tfmfd);

    if (bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa)) == -1) 
        throw std::runtime_error("MD5: bind() failed");

    int opfd = accept(tfmfd, NULL, 0);
    if (opfd == -1) throw std::runtime_error("MD5: accept() failed");
    //else
    Finally<int> opfd_cleanup([](auto fd){
        close(fd);
    }, opfd);

    if (write(opfd, data, length) == -1) 
        throw std::runtime_error("MD5: write() failed");

    if (read(opfd, result, 16) == -1) 
        throw std::runtime_error("MD5: read() failed");
}

static std::filesystem::path user_home_dir()
{
    const auto home = getenv("HOME");
    if (home) return home;
    //else
    auto  pw = getpwuid(getuid());
    return pw->pw_dir;
}

static std::filesystem::path get_proc_fd_path(int fd)
{
    static auto proc_fd = std::filesystem::path("/proc") / std::to_string(getpid()) / "fd";
    return proc_fd / std::to_string(fd);
}

static std::tuple<std::filesystem::path,std::optional<std::filesystem::path>> find_kernel_and_initramfs(const std::filesystem::path& fs_dir)
{
    std::optional<std::filesystem::path> kernel = std::nullopt;
    std::optional<std::filesystem::path> initramfs = std::nullopt;
    auto boot_dir = fs_dir / "boot";
    if (std::filesystem::is_regular_file(boot_dir / "kernel")) kernel = boot_dir / "kernel";
    else if (std::filesystem::is_regular_file(boot_dir / "vmlinuz")) kernel = boot_dir / "vmlinuz";

    if (kernel) {
        if (std::filesystem::is_regular_file(boot_dir / "initramfs")) initramfs = boot_dir / "initramfs";
        else if (std::filesystem::is_regular_file(boot_dir / "initramfs.img")) initramfs = boot_dir / "initramfs.img";
        else if (std::filesystem::is_regular_file(boot_dir / "initrd.img")) initramfs = boot_dir / "initrd.img";
        return {kernel.value(), initramfs};
    }
    //else

    // find "kernel-*" and "vmlinuz-*" under boot_dir and the latest one
    std::filesystem::file_time_type timestamp = std::filesystem::file_time_type::min();
    for (const auto& entry : std::filesystem::directory_iterator(boot_dir)) {
        if (!entry.is_regular_file()) continue;
        auto name_string = entry.path().filename().string();
        if (!name_string.starts_with("kernel-") && !name_string.starts_with("vmlinuz-")) continue;
        auto entry_timestamp = std::filesystem::last_write_time(entry);
        if (entry_timestamp > timestamp) {
            kernel = entry.path();
            timestamp = entry_timestamp;
        }
    }
    if (!kernel) throw std::runtime_error("kernel not found");
    //else
    auto pos = kernel->filename().string().find("-");
    if (pos == std::string::npos) throw std::runtime_error("invalid kernel name");
    //else
    auto suffix = kernel->filename().string().substr(pos);
    if (std::filesystem::is_regular_file(boot_dir / ("initramfs" + suffix))) initramfs = boot_dir / ("initramfs" + suffix);
    else if (std::filesystem::is_regular_file(boot_dir / ("initramfs" + suffix + ".img"))) initramfs = boot_dir / ("initramfs" + suffix + ".img");
    else if (std::filesystem::is_regular_file(boot_dir / ("initrd.img" + suffix))) initramfs = boot_dir / ("initrd.img" + suffix);

    return {*kernel, initramfs};
}

static void write_squashfs_entry_to_fd(sqfs& squashfs, sqfs_inode& dir_inode, const std::string& name, int outfd)
{
    sqfs_dir_entry entry;
    sqfs_name _name;
    sqfs_dentry_init(&entry, _name);
    //strcpy(_name, name.c_str());
    bool found;
    auto err = sqfs_dir_lookup(&squashfs, &dir_inode, name.c_str(), name.length(), &entry, &found);
    if (err != SQFS_OK) throw std::runtime_error("Failed to lookup directory entry: " + name);
    if (!found) throw std::runtime_error("Directory entry not found: " + name);
    sqfs_inode entry_inode;
    sqfs_inode_get(&squashfs, &entry_inode, entry.inode);
    //auto mtime = entry_inode.base.mtime;

    off_t bytes_already_read = 0;
    sqfs_off_t bytes_at_a_time = 64*1024;
    while (bytes_already_read < entry_inode.xtra.reg.file_size) {
        char buf[bytes_at_a_time];
        if (sqfs_read_range(&squashfs, &entry_inode, (sqfs_off_t) bytes_already_read, &bytes_at_a_time, buf) != SQFS_OK) {
            throw std::runtime_error("Failed to read range");
        }
        //else
        if (write(outfd, buf, bytes_at_a_time) < 0) throw std::runtime_error("Failed to write to file");
        bytes_already_read = bytes_already_read + bytes_at_a_time;
    }
}

static void extract_kernel_and_initramfs(sqfs& system_file, int& kernel_fd, int& initramfs_fd)
{
    sqfs_inode boot_inode;
    sqfs_inode_get(&system_file, &boot_inode, sqfs_inode_root(&system_file));
    bool found;
    sqfs_err err = sqfs_lookup_path(&system_file, &boot_inode, "boot", &found);
    if (err != SQFS_OK) throw std::runtime_error("Failed to lookup path: boot");
    if (!found) throw std::runtime_error("Path not found: boot");
    //else
    sqfs_dir boot_dir;
    if (sqfs_dir_open(&system_file, &boot_inode, &boot_dir, 0) != SQFS_OK) {
        throw std::runtime_error("Failed to open directory: boot");
    }
    //else
    sqfs_dir_entry entry;
    sqfs_name name;
    sqfs_dentry_init(&entry, name);
    std::map<std::string,std::pair<time_t,std::optional<std::string>>> entries;
    while (true) {
        bool has_next = sqfs_dir_next(&system_file, &boot_dir, &entry, &err);
        if (err != SQFS_OK) throw std::runtime_error("Failed to read directory entry");
        //else
        if (!has_next) break;
        //else
        sqfs_inode entry_inode;
        sqfs_inode_get(&system_file, &entry_inode, entry.inode);
        auto mtime = entry_inode.base.mtime;
        std::string entry_name(entry.name, entry.name_size);
        if (entry.type == SQUASHFS_REG_TYPE) {
            entries[entry_name] = {mtime, std::nullopt};
        } else if (entry.type == SQUASHFS_SYMLINK_TYPE) {
            char buf[SQUASHFS_NAME_LEN + 1];
            auto size = sizeof(buf);
            err = sqfs_readlink(&system_file, &entry_inode, buf, &size);
            if (err != SQFS_OK) throw std::runtime_error("Failed to read symlink: " + std::string(entry_name));
            //else
            entries[entry_name] = {mtime, buf};
        }
    }

    std::optional<std::string> kernel, initramfs;
    if (entries.find("vmlinuz") != entries.end()) kernel = "vmlinuz";
    else if (entries.find("kernel") != entries.end()) kernel = "kernel";
    if (kernel) {
        if (entries.find("initramfs") != entries.end()) initramfs = "initramfs";
        else if (entries.find("initramfs.img") != entries.end()) initramfs = "initramfs.img";
        else if (entries.find("initrd.img") != entries.end()) initramfs = "initrd.img";
    } else {
        time_t latest = 0;
        for (const auto& [name, mtime_and_target] : entries) {
            if (name.starts_with("vmlinuz-") || name.starts_with("kernel-")) {
                if (mtime_and_target.first > latest) {
                    kernel = name;
                    latest = mtime_and_target.first;
                }
            }
        }
        if (!kernel) throw std::runtime_error("No kernel found");
        //else
        auto pos = kernel->find("-");
        if (pos == std::string::npos) throw std::runtime_error("invalid kernel name:" + *kernel);
        //else
        auto suffix = kernel->substr(pos);
        if (entries.find("initramfs" + suffix) != entries.end()) initramfs = "initramfs" + suffix;
        else if (entries.find("initramfs" + suffix + ".img") != entries.end()) initramfs = "initramfs" + suffix + ".img";
        else if (entries.find("initrd.img" + suffix ) != entries.end()) initramfs = "initrd.img" + suffix;
    }
    if (!initramfs) {
        close(initramfs_fd);
        initramfs_fd = -1;
    }
    //else
    write_squashfs_entry_to_fd(system_file, boot_inode, entries.at(*kernel).second.value_or(*kernel), kernel_fd);
    if (initramfs && initramfs_fd >= 0) {
        write_squashfs_entry_to_fd(system_file, boot_inode, entries.at(*initramfs).second.value_or(*initramfs), initramfs_fd);
    } 
}

static std::tuple<std::filesystem::path,std::optional<std::filesystem::path>,std::optional<std::string>> 
    extract_kernel_and_initramfs(const std::filesystem::path& system_file_or_fs_dir)
{
    auto kernel_fd = memfd_create("kernel", 0);
    auto initramfs_fd = memfd_create("initramfs", 0);

    if (std::filesystem::is_regular_file(system_file_or_fs_dir)) {
        sqfs fs;
        if (sqfs_open_image(&fs, system_file_or_fs_dir.c_str(), 0) != SQFS_OK) {
            close(kernel_fd);
            close(initramfs_fd);
            throw std::runtime_error("Failed to open squashfs image");
        }
        //else
        try {
            extract_kernel_and_initramfs(fs, kernel_fd, initramfs_fd);
        }
        catch (std::exception&) {
            close(kernel_fd);
            close(initramfs_fd);
            sqfs_fd_close(fs.fd);
            throw;
        }        

        sqfs_fd_close(fs.fd);
    } else if (std::filesystem::is_directory(system_file_or_fs_dir)) {
        // copy kernel and initramfs from fs directory
        auto [kernel, initramfs] = find_kernel_and_initramfs(system_file_or_fs_dir);
        if (!initramfs) {
            close(initramfs_fd);
            initramfs_fd = -1;
        }
        // copy kernel to kernel_fd
        int fd = open(kernel.c_str(), O_RDONLY);
        if (fd < 0) {
            close(kernel_fd);
            if (initramfs_fd >= 0) close(initramfs_fd);
            throw std::runtime_error("open() failed");
        }
        //else
        uint8_t buf[1024];
        ssize_t r;
        while ((r = read(fd, buf, sizeof(buf))) > 0) {
            write(kernel_fd, buf, r);
        }
        close(fd);
        if (initramfs) {
            // copy initramfs to initramfs_fd
            fd = open(initramfs->c_str(), O_RDONLY);
            if (fd < 0) {
                close(kernel_fd);
                close(initramfs_fd);
                throw std::runtime_error("open() failed");
            }
            //else
            while ((r = read(fd, buf, sizeof(buf))) > 0) {
                write(initramfs_fd, buf, r);
            }
            close(fd);
        }   
    } else {
        close(kernel_fd);
        close(initramfs_fd);
        throw std::runtime_error("system file or fs directory not found");
    }

    // rewind kernel fd and check if it's gzipped
    if (lseek(kernel_fd, 0, SEEK_SET) == (off_t)-1) {
        close(kernel_fd);
        if (initramfs_fd >= 0) close(initramfs_fd);
        throw std::runtime_error("lseek() failed");
    }
    uint8_t magic[2];
    if (read(kernel_fd, magic, sizeof(magic)) < 0) {
        close(kernel_fd);
        if (initramfs_fd >= 0) close(initramfs_fd);
        throw std::runtime_error("read() failed");
    }

    if (magic[0] == 0x1f && magic[1] == 0x8b) { // simply gzip'ed kernel
        // kernel is gzipped
        auto kernel_unzipped_fd = memfd_create("kernel_unzipped", 0);
        auto gzip_pid = fork();
        if (gzip_pid < 0) {
            close(kernel_fd);
            if (initramfs_fd >= 0) close(initramfs_fd);
            throw std::runtime_error("fork() failed");
        }
        //else
        if (gzip_pid == 0) {
            close(STDOUT_FILENO);
            dup2(kernel_unzipped_fd, STDOUT_FILENO);
            _exit(execlp("gunzip", "gunzip", "-c", get_proc_fd_path(kernel_fd).c_str(), NULL));
        }
        int gzip_wstatus;
        waitpid(gzip_pid, &gzip_wstatus, 0);
        if (!WIFEXITED(gzip_wstatus) || WEXITSTATUS(gzip_wstatus) != 0) {
            close(kernel_fd);
            if (initramfs_fd >= 0) close(initramfs_fd);
            throw std::runtime_error("gunzip failed");
        }
        //else
        close(kernel_fd);
        kernel_fd = kernel_unzipped_fd;
    }

    if (magic[0] == 'M' && magic[1] == 'Z') { // PE image
        // check if kernel is self-extracting(EFI_ZBOOT) image
        uint8_t zimg_header[26];
        if (read(kernel_fd, zimg_header, sizeof(zimg_header)) < 0) {
            close(kernel_fd);
            if (initramfs_fd >= 0) close(initramfs_fd);
            throw std::runtime_error("read() failed");
        }
        if (memcmp(zimg_header, "\0\0zimg", 5) == 0 && memcmp(zimg_header + 22, "gzip", 4) == 0) {
            // kernel is self-extracting image
            // find gzip header from trailing
            uint8_t buffer_to_find_gzip_header_from_the_rest[65536];
            if (read(kernel_fd, buffer_to_find_gzip_header_from_the_rest, sizeof(buffer_to_find_gzip_header_from_the_rest)) < 0) {
                close(kernel_fd);
                if (initramfs_fd >= 0) close(initramfs_fd);
                throw std::runtime_error("read() failed");
            }
            std::string_view gzip_haader("\x1f\x8b\x08\x00\x00\x00\x00\x00", 8);
            auto gzip_offset = std::string_view(reinterpret_cast<char*>(buffer_to_find_gzip_header_from_the_rest), sizeof(buffer_to_find_gzip_header_from_the_rest)).find(gzip_haader);
            if (gzip_offset == std::string_view::npos) {
                close(kernel_fd);
                if (initramfs_fd >= 0) close(initramfs_fd);
                throw std::runtime_error("gzip header not found");
            }
            //else(gzip header found)
            // rewind kernel_fd to 2 + 26 + gzip_offset
            if (lseek(kernel_fd, 2 + 26 + gzip_offset, SEEK_SET) == (off_t)-1) {
                close(kernel_fd);
                if (initramfs_fd >= 0) close(initramfs_fd);
                throw std::runtime_error("lseek() failed");
            }
            auto kernel_unzipped_fd = memfd_create("kernel_unzipped", 0);
            auto gzip_pid = fork();
            if (gzip_pid < 0) {
                close(kernel_fd);
                if (initramfs_fd >= 0) close(initramfs_fd);
                throw std::runtime_error("fork() failed");
            }
            //else
            if (gzip_pid == 0) {
                close(STDOUT_FILENO);
                dup2(kernel_unzipped_fd, STDOUT_FILENO);
                close(STDIN_FILENO);
                dup2(kernel_fd, STDIN_FILENO);
                _exit(execlp("gunzip", "gunzip", "-c", NULL));
            }
            int gzip_wstatus;
            waitpid(gzip_pid, &gzip_wstatus, 0);
            // in this case, gzip may return non-zero exit status because it's not a regular gzip file.
            // so we don't check exit status here.
            close(kernel_fd);
            kernel_fd = kernel_unzipped_fd;
        }
    }

    // determine kernel's CPU architecture
    // rewind kernel fd
    if (lseek(kernel_fd, 0, SEEK_SET) == (off_t)-1) throw std::runtime_error("lseek() failed");
    // read kernel's magic number
    uint8_t buf[518];
    auto size = read(kernel_fd, buf, sizeof(buf));
    if (size < 0) throw std::runtime_error("read() failed");
    std::optional<std::string> arch;
    if (buf[514] == 'H' && buf[515] == 'd' && buf[516] == 'r' && buf[517] == 'S') {
        arch = "x86_64";
    } else if (buf[0x38] == 0x41 && buf[0x39] == 0x52 && buf[0x3a] == 0x4d && buf[0x3b] == 0x64) {
        arch = "aarch64";
    } else if (buf[0x30] == 'R' && buf[0x31] == 'I' && buf[0x32] == 'S' && buf[0x33] == 'C' && buf[0x34] == 'V') {
        arch = "riscv64";
    }

    return {
        get_proc_fd_path(kernel_fd),
        initramfs_fd >= 0? std::optional(get_proc_fd_path(initramfs_fd)) : std::nullopt,
        arch
    };
}

static std::optional<std::string> get_default_hostname(const std::filesystem::path& system_file)
{
    auto artifact_fd = memfd_create("artifact", 0);
    auto unsquashfs_pid = fork();
    if (unsquashfs_pid < 0) throw std::runtime_error("fork() failed");
    //else
    if (unsquashfs_pid == 0) {
        close(STDOUT_FILENO);
        dup2(artifact_fd, STDOUT_FILENO);
        _exit(execlp("unsquashfs", "unsquashfs", "-q", "-cat", system_file.c_str(), ".genpack/artifact", NULL));
    }
    int unsquashfs_wstatus;
    waitpid(unsquashfs_pid, &unsquashfs_wstatus, 0);
    if (!WIFEXITED(unsquashfs_wstatus) || WEXITSTATUS(unsquashfs_wstatus) != 0) {
        close(artifact_fd);
        return std::nullopt;
    }
    //else
    if (lseek(artifact_fd, 0, SEEK_SET) == (off_t)-1) throw std::runtime_error("lseek() failed");
    //else
    char buf[HOST_NAME_MAX];
    auto size = read(artifact_fd, buf, sizeof(buf) - 1);
    close(artifact_fd);
    buf[size] = '\0';
    return buf;
}

static std::filesystem::path create_temporary_data_file(bool format = true)
{
    auto data_fd = memfd_create("data", 0);
    ftruncate(data_fd, 1024 * 1024 * 512/*512MB*/);
    auto data_fd_path = get_proc_fd_path(data_fd);
    if (format) {
        auto mkbtrfs_pid = fork();
        if (mkbtrfs_pid < 0) throw std::runtime_error("fork() failed");
        //else
        if (mkbtrfs_pid == 0) {
            _exit(execlp("mkfs.btrfs", "mkfs.btrfs", "-q", "-f", data_fd_path.c_str(), NULL));
        }
        int mkbtrfs_wstatus;
        waitpid(mkbtrfs_pid, &mkbtrfs_wstatus, 0);
        if (!WIFEXITED(mkbtrfs_wstatus) || WEXITSTATUS(mkbtrfs_wstatus) != 0) 
            throw std::runtime_error("mkfs.btrfs failed");
    }

    return data_fd_path;
}

static std::filesystem::path create_dummy_block_file(const std::string name)
{
    auto fd = memfd_create(name.c_str(), 0);
    ftruncate(fd, 1024 * 4/*4kb*/);
    return get_proc_fd_path(fd);
}

static std::string generate_temporary_hostname()
{
    uint8_t buf[4];
    auto fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) throw std::runtime_error("open(\"/dev/urandom\") failed");
    read(fd, buf, sizeof(buf));
    close(fd);
    char hostname[32];
    sprintf(hostname, "host-%02x%02x%02x%02x", (int)buf[0], (int)buf[1], (int)buf[2], (int)buf[3]);
    return hostname;
}

static int sock_connect(const std::filesystem::path& sock_path)
{
    struct sockaddr_un sockaddr;
    memset(&sockaddr, 0, sizeof(sockaddr));
    auto sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) throw std::runtime_error("socket() failed");
    sockaddr.sun_family = AF_UNIX;
    strcpy(sockaddr.sun_path, sock_path.c_str());
    if (connect(sock, (const struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
        close(sock);
        return -1;
    }
    //else
    return sock;
}

static auto qmp_connect(const std::string& vmname) {return sock_connect(run_dir::qmp_sock(vmname));}

static bool qmp_ping(const std::string& vmname)
{
    auto qmp_fd = qmp_connect(vmname);
    if (qmp_fd < 0) return false;
    //else
    try {
        receive_message(qmp_fd);
    }
    catch (std::runtime_error&) {
        return false;
    }
    shutdown(qmp_fd, SHUT_WR);
    close(qmp_fd);
    return true;
}

static bool qmp_shutdown(const std::string& vmname, bool force)
{
    auto qmp_fd = qmp_connect(vmname);
    if (qmp_fd < 0) return false;
    //else
    receive_message(qmp_fd);
    nlohmann::json capabilities_req;
    capabilities_req["execute"] = "qmp_capabilities";
    execute_query(qmp_fd, capabilities_req);
    nlohmann::json shutdown_req;
    shutdown_req["execute"] = force? "quit" : "system_powerdown";
    execute_query(qmp_fd, shutdown_req);
    shutdown(qmp_fd, SHUT_WR);
    close(qmp_fd);
    return true;
}

static bool is_o_direct_supported(const std::filesystem::path& file)
{
    auto r = open(file.c_str(), O_RDONLY | O_DIRECT);
    if (r < 0) return false;
    //else
    close(r);
    return true;
}

struct RunOptions {
    const std::optional<std::string>& name = std::nullopt;
    const std::optional<std::filesystem::path>& virtiofs_path = std::nullopt;
    const std::optional<std::filesystem::path>& p9_path = std::nullopt;
    const uint32_t memory = default_memory_size;
    const uint16_t cpus = 1;
    const std::optional<bool> kvm = std::nullopt;
    const std::vector<std::tuple<netif::type::Some,std::optional<std::string>/*mac address*/,bool/*vhost*/>>& net = {};
    const std::vector<std::string> hostfwd = {};
    const std::vector<std::filesystem::path>& usb = {};
    const std::vector<std::pair<std::filesystem::path,bool/*virtio*/>>& disks = {};
    const std::vector<std::string>& pci = {};
    const std::optional<std::filesystem::path>& cdrom = std::nullopt;
    const std::optional<std::string>& append = std::nullopt;
    const std::optional<std::string>& display = std::nullopt;
    const std::optional<std::string>& spice = std::nullopt;
    const std::optional<std::string>& vnc = std::nullopt;
    enum class accel_t { qxl, _2d, opengl, vulkan };
    static accel_t to_accel(const std::string& accel) {
        if (accel == "qxl") return accel_t::qxl;
        if (accel == "2d") return accel_t::_2d;
        if (accel == "opengl") return accel_t::opengl;
        if (accel == "vulkan") return accel_t::vulkan;
        throw std::runtime_error("Invalid accel: " + accel);
    }
    const accel_t accel = accel_t::_2d;
    const uint16_t gpu_max_outputs = 1;
    const std::optional<std::string>& rendernode = std::nullopt;
    const bool hvc = false;
    const bool stdio_console = false;
    const bool no_shutdown = false;
    const std::map<std::string,std::string>& firmware_strings = {};
    const std::map<std::string,std::filesystem::path>& firmware_files = {};
    const std::map<std::string,std::string>& qemu_env = {};
    const std::optional<uint64_t> virtiofs_rlimit_nofile = {};
    const std::optional<std::string> virtiofs_cache = {};
    const std::optional<std::string> virtiofs_inode_file_handles = {};
    const std::optional<std::string>& logging_items = std::nullopt;
    const std::optional<std::string>& trace = std::nullopt;
    const std::optional<std::filesystem::path>& logfile = std::nullopt;
};

struct VirtiofsdOptions {
    const std::optional<uint64_t> rlimit_nofile = std::nullopt;
    const std::optional<std::string> cache = std::nullopt;
    const std::optional<std::string> inode_file_handles = std::nullopt;
};

static pid_t run_virtiofsd(const std::string& vmname, const std::filesystem::path& path, const VirtiofsdOptions& options)
{
    auto sock = run_dir::virtiofs_sock(vmname);
    try {
        std::filesystem::remove(sock);
    }
    catch (std::filesystem::filesystem_error&) {}
    auto pid = fork();
    if (pid < 0) throw std::runtime_error("fork() failed");
    if (pid == 0) {
        std::vector<std::string> args;
        if (getuid() != 0) {
            args.insert(args.end(), {
                "/usr/bin/podman", "unshare"
            });
        }
        args.insert(args.end(), {
            "/usr/libexec/virtiofsd", 
            "--allow-direct-io", "--xattr", "--posix-acl",
            // modcaps must be modified to allow virtiofs to be used as an upper layer of overlayfs
            "--modcaps=+sys_admin:+sys_resource:+fowner:+setfcap",
            // cache must be "auto" to enable mmap(MAP_SHARED)
            "--cache", options.cache.value_or("auto"), 
            "--socket-path", sock.string(), "--shared-dir", path.string(),
            // "--inode-file-handles=prefer" is necessary to save number of file descriptors
            "--inode-file-handles=" + options.inode_file_handles.value_or("prefer")
        });
        if (options.rlimit_nofile.has_value()) {
            args.push_back("--rlimit-nofile");
            args.push_back(std::to_string(*options.rlimit_nofile));
        }

        std::vector<char*> c_args;
        for (auto& arg:args) { c_args.push_back(&arg[0]); }
        c_args.push_back(NULL);
        _exit(execvp(c_args[0], c_args.data()));
    }
    //else
    int count = 0;
    while (!std::filesystem::is_socket(sock)) {
        if (count == 0) std::cout << "Waiting for virtiofsd to start..." << std::endl;
        usleep(100000);
        if (++count > 100) {
            kill(pid, SIGKILL);
            throw std::runtime_error("virtiofsd failed to start");
        }
    }

    return pid;
}

static std::optional<std::filesystem::path> generate_ssh_host_keys_archive(const std::string& vmname)
{
    auto ssh_host_key_root = run_dir::vm_dir(vmname) / "ssh-host-key";
    auto ssh_host_key_dir = ssh_host_key_root / "etc" / "ssh";
    std::filesystem::create_directories(ssh_host_key_dir);

    auto ssh_keygen = fork();
    if (ssh_keygen < 0) return std::nullopt;
    //else
    if (ssh_keygen == 0) {
        _exit(execlp("ssh-keygen", "ssh-keygen", "-A", "-f", ssh_host_key_root.c_str(), NULL));
    }
    //else
    int ssh_keygen_wstatus;
    if (waitpid(ssh_keygen, &ssh_keygen_wstatus, 0) < 0 || !WIFEXITED(ssh_keygen_wstatus) || WEXITSTATUS(ssh_keygen_wstatus) != 0) 
        return std::nullopt;
    //else
    auto wfd = memfd_create("ssh-host-keys", 0);
    if (wfd < 0) return std::nullopt;
    fchmod(wfd, S_IRUSR);
    auto tar = fork();
    if (tar < 0) return std::nullopt;
    //else
    if (tar == 0) {
        dup2(wfd, STDOUT_FILENO);
        _exit(execlp("tar", "tar", "cf", "-", "-C", ssh_host_key_dir.c_str(), ".", NULL));
    }
    //else
    int tar_wstatus;
    if (waitpid(tar, &tar_wstatus, 0) < 0 || !WIFEXITED(tar_wstatus) || WEXITSTATUS(tar_wstatus) != 0) {
        close(wfd);
        return std::nullopt;
    }
    //else
    return get_proc_fd_path(wfd);
}

static std::optional<std::filesystem::path> generate_ssh_public_keys(const std::string& vmname)
{
    auto wfd = memfd_create("ssh-public-keys", 0);
    if (wfd < 0) return std::nullopt;
    //else
    auto cat = [](const std::filesystem::path& src, int wfd) {
        auto rfd = open(src.c_str(), O_RDONLY);
        if (rfd < 0) return false;
        //else
        uint8_t buf[1024];
        ssize_t r;
        size_t cnt = 0;
        while ((r = read(rfd, buf, sizeof(buf))) > 0 && cnt < 1024 * 1024/*Max 1MB*/) {
            write(wfd, buf, r);
            cnt += r;
        }
        close(rfd);
        return (r == 0);
    };
    const std::filesystem::path ssh_dir = user_home_dir() / ".ssh";
    auto authorized_keys = ssh_dir / "authorized_keys";
    if (std::filesystem::exists(authorized_keys) && std::filesystem::is_regular_file(authorized_keys)) {
        cat(authorized_keys, wfd);
    }
    std::vector<std::filesystem::path> ssh_public_key_candidates = {"id_ecdsa.pub", "id_ed25519.pub", "id_rsa.pub"};
    for (const auto& ssh_public_key_candidate:ssh_public_key_candidates) {
        auto ssh_public_key = ssh_dir / ssh_public_key_candidate;
        if (std::filesystem::exists(ssh_public_key) && std::filesystem::is_regular_file(ssh_public_key)) {
            cat(ssh_public_key, wfd);
        }
    }
    if (lseek(wfd, 0, SEEK_CUR) == 0) {
        close(wfd);
        return std::nullopt;
    }
    //else
    return get_proc_fd_path(wfd);
}

static std::optional<std::filesystem::path> generate_application_ini_file(const dictionary* ini)
{
    const char* section_name = "application";
    int nkeys = iniparser_getsecnkeys(ini, section_name);
    if (nkeys == 0) return std::nullopt;
    //else
    const char** seckeys = (const char**)malloc(sizeof(char*) * nkeys);
    if (!seckeys) throw std::runtime_error("malloc() failed");
    auto fd = memfd_create("application.ini", 0);
    // fd
    if (iniparser_getseckeys(ini, section_name, seckeys)) {
        for (int i = 0; i < nkeys; i++) {
            const char* key = seckeys[i];
            std::string line(key + strlen(section_name) + 1);
            line += '=';
            line += iniparser_getstring(ini, key, "");
            line += '\n';
            write(fd, line.c_str(), line.length());
        }
    }
    free(seckeys);
    return get_proc_fd_path(fd);
}

static void apply_common_args_to_qemu_cmdline(const std::string& vmname, std::vector<std::string>& qemu_cmdline)
{
    qemu_cmdline.insert(qemu_cmdline.end(), {
        "-nodefaults", "-device", "usb-ehci", "-device", "usb-kbd", "-device", "usb-tablet", "-rtc", "base=utc",
        "-monitor", "unix:" + run_dir::monitor_sock(vmname).string() + ",server,nowait",
        "-qmp", "unix:" + run_dir::qmp_sock(vmname).string() + ",server,nowait",
        "-chardev", "socket,path=" + run_dir::qga_sock(vmname).string() + ",server=on,wait=off,id=qga0",
        "-device", "virtio-serial", "-device", "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0",
        "-fw_cfg", "opt/vmname,string=" + vmname,
        "-pidfile", run_dir::qemu_pid(vmname)
    });

    // generate ssh host key which valid till next reboot
    auto ssh_host_keys_archive = generate_ssh_host_keys_archive(vmname);
    if (ssh_host_keys_archive.has_value()) {
        qemu_cmdline.insert(qemu_cmdline.end(), {
            "-fw_cfg", "opt/ssh-host-keys,file=" + ssh_host_keys_archive.value().string()
        });
    }

    // provide ssh public keys through QEMU's fw_cfg
    auto ssh_public_keys = generate_ssh_public_keys(vmname);
    if (ssh_public_keys.has_value()) {
        qemu_cmdline.insert(qemu_cmdline.end(), {
            "-fw_cfg", "opt/ssh-public-key,file=" + ssh_public_keys.value().string()
        });
    }
}

static bool is_emulation_needed(const std::string& arch)
{
    // get the host's architecture
    struct utsname uts;
    if (uname(&uts) < 0) throw std::runtime_error("uname() failed");
    //else
    return (arch != uts.machine);
}

struct qemu_os_resources {
    std::optional<int> vm_run_dir_lock_fd;
    std::vector<int> pci_locks;
    std::optional<pid_t> virtiofsd_pid;
    std::set<int> fds;
    ~qemu_os_resources() {
        for (auto fd:fds) close(fd);

        if (virtiofsd_pid.has_value() && *virtiofsd_pid > 0) {
            std::cout << "Shutting down virtiofsd..." << std::endl;
            kill(*virtiofsd_pid, SIGTERM);
            waitpid(*virtiofsd_pid, NULL, 0);
        }

        if (vm_run_dir_lock_fd.has_value() && *vm_run_dir_lock_fd >= 0) {
            flock(*vm_run_dir_lock_fd, LOCK_UN);
            close(*vm_run_dir_lock_fd);
        }

        for (auto pci_lock:pci_locks) {
            flock(pci_lock, LOCK_UN);
            close(pci_lock);
        }
    }
};

static std::string get_system_timezone()
{
    std::array<char, 128> buffer;
    std::string result;
    auto deleter = [](FILE* fp) { pclose(fp); };
    std::unique_ptr<FILE, decltype(deleter)> pipe(popen("timedatectl show -p Timezone --value", "r"), deleter);
    if (!pipe) {
        return "Error: Failed to execute command";
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    if (!result.empty() && result.back() == '\n') {
        result.pop_back();
    }
    return result;
}

static uint32_t/*cid*/ apply_options_to_qemu_cmdline(const std::string& vmname, 
    std::vector<std::string>& qemu_cmdline, const RunOptions& options, const std::string& arch, qemu_os_resources& os_resources,
    bool bios = false)
{
    // name
    qemu_cmdline.push_back("-name");
    qemu_cmdline.push_back(vmname);

    // logging
    if (options.logging_items) {
        qemu_cmdline.insert(qemu_cmdline.end(), {"-d", *options.logging_items});
    }
    if (options.trace) {
        qemu_cmdline.insert(qemu_cmdline.end(), {"-trace", *options.trace});
    }
    if (options.logfile) {
        qemu_cmdline.insert(qemu_cmdline.end(), {"-D", options.logfile->string()});
    }

    // machine
    auto machine_type = [&arch,bios]() {
        if (arch == "x86_64") return bios? "q35" : "pc";
        //else 
        if (bios) throw std::runtime_error("BIOS is only supported on x86_64");
        //else
        return "virt";
    }();
    bool kvm = options.kvm.value_or(access("/dev/kvm", R_OK|W_OK) == 0) && !is_emulation_needed(arch);
    auto machine_accel = kvm? "kvm" : "tcg";
    auto machine_str = std::string("type=") + machine_type + ",accel=" + machine_accel;
    qemu_cmdline.insert(qemu_cmdline.end(), {"-machine", machine_str});
    qemu_cmdline.push_back("-cpu");
    qemu_cmdline.push_back(kvm? "host" : "max");

    // memory
    qemu_cmdline.insert(qemu_cmdline.end(), {
        "-m", std::to_string(options.memory),
        "-object", "memory-backend-memfd,id=mem,size=" + std::to_string(options.memory) + "M,share=on", "-numa", "node,memdev=mem",
    });

    // display
    if (options.spice || options.vnc) {
        std::string graphics_device = [](const auto& accel) -> std::string {
            if (accel == RunOptions::accel_t::_2d) return "virtio-gpu";
            if (accel == RunOptions::accel_t::qxl) return "qxl,vgamem_mb=128";
            //else
            std::string device("virtio-gpu-gl,iommu_platform=on,hostmem=2G,blob=true");
            if (accel == RunOptions::accel_t::vulkan) device += ",venus=true";
            return device;
        }(options.accel);
        if (options.gpu_max_outputs > 1) {
            graphics_device += ",max_outputs=" + std::to_string(options.gpu_max_outputs);
        }
        qemu_cmdline.insert(qemu_cmdline.end(), {
            "-display", options.display.value_or("egl-headless" + (options.rendernode? ",rendernode=" + *options.rendernode : "")),
            "-device", graphics_device,
            "-chardev", "spicevmc,id=vdagent,name=vdagent",
            "-device", "virtio-serial-pci", "-device", "virtserialport,chardev=vdagent,name=com.redhat.spice.0",
            "-audiodev", "spice,id=snd0",
            "-device", "virtio-sound-pci,audiodev=snd0"
        });
        if (options.spice) {
            qemu_cmdline.insert(qemu_cmdline.end(), {"-spice", *options.spice});
        }
        if (options.vnc) {
            qemu_cmdline.insert(qemu_cmdline.end(), {"-vnc", *options.vnc});
        }
    } else if (options.display) {
        qemu_cmdline.insert(qemu_cmdline.end(), {"-display", *options.display});
        qemu_cmdline.insert(qemu_cmdline.end(), {"-vga", "virtio"});
    } else {
        qemu_cmdline.insert(qemu_cmdline.end(), {"-display", "none"});
    }

    // Console (Legacy serial, or HVC)
    if (options.hvc) {
        qemu_cmdline.insert(qemu_cmdline.end(), {
            "-device", "virtio-serial-pci", "-device", "virtconsole,chardev=hvc",
            "-chardev", (options.stdio_console? "stdio,signal=off,id=hvc" : "socket,path=" + run_dir::console_sock(vmname).string() + ",server=on,wait=off,id=hvc")
        }); 
    } else {
        qemu_cmdline.insert(qemu_cmdline.end(), {
            "-serial",
            (options.stdio_console? "mon:stdio" : "unix:" + run_dir::console_sock(vmname).string() + ",server=on,wait=off")
        });
    }
    // Number of CPU core
    if (options.cpus > 1) {
        qemu_cmdline.insert(qemu_cmdline.end(), {"-smp", "cpus=" + std::to_string(options.cpus)});
    }
    // Disks
    for (const auto& [disk,virtio] : options.disks) {
        qemu_cmdline.insert(qemu_cmdline.end(), {"-drive", "file=" + disk.string() + ",format=raw,media=disk"
            + (virtio? ",if=virtio" : "")
            + (!bios && is_o_direct_supported(disk)? ",aio=native,cache.direct=on":"") });
    }
    // Passthrough PCI devices
    std::vector<std::string> vfio_pci_devices;
    // find SR-IOV VFs from network interfaces and make them available to the VM through vfio-pci
    for (const auto& [net,macaddr,vhost]:options.net) {
        // macaddr and vhost are not used here
        if (!std::holds_alternative<netif::type::SRIOV>(net)) continue;
        //else
        auto [pf_name, vf_start, vf_count] = std::get<netif::type::SRIOV>(net);
        int lock = -1; // no lock yet
        for (int i = vf_start; i < vf_start + vf_count; i++) {
            auto pci_id = netif::get_vf_pci_id(pf_name, i);
            if (!pci_id) continue;
            //else
            lock = run_dir::lock_pci(*pci_id);
            if (lock < 0) continue;
            //else
            os_resources.pci_locks.push_back(lock);
            vfio_pci_devices.push_back(*pci_id);
            break;
        }
        if (lock < 0) {
            throw std::runtime_error("Failed to acquire SR-IOV VF from PF " + pf_name);
        }
    }
    vfio_pci_devices.insert(vfio_pci_devices.end(), options.pci.begin(), options.pci.end());
    for (const auto& pci : vfio_pci_devices) {
        pci::replace_driver_with_vfio(pci);
        qemu_cmdline.push_back("-device");
        qemu_cmdline.push_back("vfio-pci,host=" + pci);
    }
    // Network interfaces
    int net_num = 0;
    bool has_user_net = false;
    for (const auto& [net,macaddr,vhost]:options.net) {
        if (std::holds_alternative<netif::type::SRIOV>(net)) continue; // Already handled
        auto generate_macaddr_from_name = [](const std::string& vmname, int num) {
            std::string name = vmname + ":" + std::to_string(num);
            unsigned char buf[16];
            MD5((const uint8_t*)name.c_str(), name.length(), buf);
            uint8_t mac[6] = { 0x52, 0x54, 0x00, 0x00, 0x00, 0x00 };
            mac[3] = buf[0] & 0x7f;
            mac[4] = buf[1];
            mac[5] = buf[2];
            char mac_str[18];
            sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", (int)mac[0], (int)mac[1], (int)mac[2], (int)mac[3], (int)mac[4], (int)mac[5]);
            return std::string(mac_str);
        };
        const auto net_id = "net" + std::to_string(net_num);
        std::string _macaddr = macaddr.value_or(generate_macaddr_from_name(vmname, net_num));
        std::string netdev = [&net_id,&net,&vhost,&_macaddr,&os_resources]() {
            if (std::holds_alternative<netif::type::User>(net)) {
                return "user,id=" + net_id;
            } else if (std::holds_alternative<netif::type::Bridge>(net)) {
                std::string bridge = std::get<netif::type::Bridge>(net).name;
                //return std::format("tap,id={},br={},helper=/usr/libexec/qemu-bridge-helper{}", net_id, bridge, vhost? ",vhost=on" : "");
                //suspend using std::format as gcc12 doesn't support it
                return "tap,id=" + net_id + ",br=" + bridge + ",helper=/usr/libexec/qemu-bridge-helper" + (vhost? ",vhost=on" : "");
            } else if (std::holds_alternative<netif::type::Tap>(net)) {
                std::string tap = std::get<netif::type::Tap>(net).name;
                //return std::format("tap,id={},ifname={},script=no,downscript=no{}", net_id, tap, vhost? ",vhost=on" : "");
                return "tap,id=" + net_id + ",ifname=" + tap + ",script=no,downscript=no" + (vhost? ",vhost=on" : "");
            } else if (std::holds_alternative<netif::type::Mcast>(net)) {
                std::string mcast = std::get<netif::type::Mcast>(net).addr;
                return "socket,id=" + net_id + ",mcast=" + mcast;
            } else if (std::holds_alternative<netif::type::MACVTAP>(net)) {
                std::string macvtap = std::get<netif::type::MACVTAP>(net).name;
                const auto [macaddr, fd] = netif::open_macvtap(macvtap);
                _macaddr = macaddr;
                os_resources.fds.insert(fd);
                return "tap,id=" + net_id + ",fd=" + std::to_string(fd) + (vhost? ",vhost=on" : "");
            } else
                throw std::runtime_error("Invalid network type");
        }();

        if (netdev.starts_with("user,")) {
            if (has_user_net) throw std::runtime_error("Only one user network interface is allowed");
            //else
            std::string hostfwd_str;
            for (const auto& hostfwd:options.hostfwd) {
                hostfwd_str += ",hostfwd=" + hostfwd;
            }
            netdev += hostfwd_str;
        }
        //const auto device = std::format("virtio-net-pci,romfile=,netdev={},mac={}", net_id, _macaddr);
        const auto device = "virtio-net-pci,romfile=,netdev=" + net_id + ",mac=" + _macaddr;
        // TODO: apply tap
        qemu_cmdline.insert(qemu_cmdline.end(), {
            "-netdev", netdev, 
            "-device", device
        });
        net_num++;
    }

    // vsock
    uint32_t guest_cid = vsock::determine_guest_cid(vmname);
    qemu_cmdline.insert(qemu_cmdline.end(), {
        "-device", "vhost-vsock-pci,guest-cid=" + std::to_string(guest_cid)
    });

    // USB devices
    if (options.usb.size() > 0) {
        qemu_cmdline.push_back("-usb");
        for (const auto& dev:options.usb) {
            // dev is a path to the USB device like /dev/bus/usb/001/002 (001=bus id, 002=device id)
            auto bus_id = std::stoi(dev.parent_path().filename().string());
            auto dev_id = std::stoi(dev.filename().string());
            auto unbind_file = std::filesystem::path("/sys/bus/usb/devices") / (std::to_string(bus_id) + "-" + std::to_string(dev_id)) / "driver/unbind";
            if (std::filesystem::exists(unbind_file)) {
                {
                    std::ofstream ofs(unbind_file);
                    ofs << std::to_string(bus_id) + "-" + std::to_string(dev_id);
                }
                if (std::filesystem::exists(unbind_file)) {
                    throw std::runtime_error("Failed to unbind USB device " + dev.string());
                }
            }
            std::cout << "Passing through USB device " << dev.string() << std::endl;
            qemu_cmdline.insert(qemu_cmdline.end(), {
                "-device", "usb-host,hostdevice=" + dev.string()
            });
        }
    }
    // CDROM
    if (options.cdrom.has_value()) {
        qemu_cmdline.insert(qemu_cmdline.end(), {
            "-cdrom", options.cdrom.value().string()
        });
    }

    // pass timezone(read from /etc/timezone) to the VM
    const auto timezone = get_system_timezone();
    if (!timezone.empty()) {
        qemu_cmdline.insert(qemu_cmdline.end(), {
            "-fw_cfg", "opt/timezone,string=" + timezone
        });
    }

    // pass lang to the VM
    const auto lang = getenv("LANG");
    if (lang && strlen(lang) > 0) {
        qemu_cmdline.insert(qemu_cmdline.end(), {
            "-fw_cfg", "opt/lang,string=" + std::string(lang)
        });
    }

    // strings/files to be passed through fw_cfg
    for (const auto& [name,string]:options.firmware_strings) {
        if (name.find(',') != name.npos) throw std::runtime_error("Name cannot contain ','");
        qemu_cmdline.insert(qemu_cmdline.end(), {
            "-fw_cfg", "opt/" + name + ",string=" + string
        });
    }
    for (const auto& [name,file]:options.firmware_files) {
        if (name.find(',') != name.npos) throw std::runtime_error("Name cannot contain ','");
        // check if file really exists and it's a regular file
        if (!std::filesystem::exists(file) || !std::filesystem::is_regular_file(file)) {
            throw std::runtime_error(file.string() + " does not exist or it's not a regular file");
        }
        // check if the file size is not too large
        if (std::filesystem::file_size(file) > 1024 * 1024 * 4L/*4MB*/) {
            throw std::runtime_error(file.string() + " is too large(make it less than 4MB)");
        }
        qemu_cmdline.insert(qemu_cmdline.end(), {
            "-fw_cfg", "opt/" + name + ",file=" + file.string()
        });
    }
    
    if (options.no_shutdown) {
        qemu_cmdline.push_back("-no-shutdown");
    }

    // 9p filesystem
    if (options.p9_path) {
        qemu_cmdline.insert(qemu_cmdline.end(), {
            "-virtfs", "local,path=" + options.p9_path->string() + ",mount_tag=fs,security_model=none,writeout=immediate"
        });
    }

    return guest_cid;
}

static void apply_virtiofs_to_qemu_cmdline(const std::string& vmname, std::vector<std::string>& qemu_cmdline, pid_t virtiofsd_pid)
{
    qemu_cmdline.insert(qemu_cmdline.end(), {
        "-chardev", "socket,id=virtiofs,path=" + run_dir::virtiofs_sock(vmname).string(),
        "-device", "vhost-user-fs-pci,queue-size=1024,chardev=virtiofs,tag=fs"
    });
}

static int run_qemu(const std::string& vmname, const std::vector<std::string>& cmdline, 
    const std::map<std::string,std::string>& qemu_env, pid_t virtiofsd_pid = -1)
{
    auto qemu_pid = fork();
    if (qemu_pid < 0) throw std::runtime_error("fork() failed");
    if (qemu_pid == 0) { // child process
        for (const auto&[name,value]:qemu_env) {
            setenv(name.c_str(), value.c_str(), 1);
        }
        char ** argv = new char *[cmdline.size() + 1];
        for (int i = 0; i < cmdline.size(); i++) {
            argv[i] = strdup(cmdline[i].c_str());
        }
        argv[cmdline.size()] = NULL;
        _exit(execvp(cmdline[0].c_str(), argv));
    }

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGHUP);
    sigprocmask(SIG_SETMASK, &mask, NULL);
    auto sigfd = signalfd(-1, &mask, SFD_CLOEXEC);
    if (sigfd < 0) throw std::runtime_error("signalfd() failed");
    struct pollfd pollfds[1];
    bool qemu_ready_notified = false;
    while (true) {
        if (!qemu_ready_notified && qmp_ping(vmname)) {
            sd_notify(0, "READY=1");
            qemu_ready_notified = true;
            std::cout << "QEMU is running." << std::endl;
        }
        pollfds[0].fd = sigfd;
        pollfds[0].events = POLLIN;
        if (poll(pollfds, 1, qemu_ready_notified? 1000 : 100) < 0) throw std::runtime_error("poll() failed");
        if (pollfds[0].revents & POLLIN) {
            struct signalfd_siginfo info;
            if (read(pollfds[0].fd, &info, sizeof(info)) != sizeof(info)) 
                throw std::runtime_error(std::string("read(sigal fd) failed: ") + strerror(errno));
            //else
             if (info.ssi_signo == SIGTERM || info.ssi_signo == SIGINT) {
                sd_notify(0, "STOPPING=1");
                std::cout << "Terminating QEMU..." << std::endl;
                if (!qmp_shutdown(vmname, false)) {
                    std::cout << "QMP is not responsing. force terminating QEMU..." << std::endl;
                    kill(qemu_pid, SIGTERM);
                }
             } else if (info.ssi_signo == SIGCHLD) {
                if (info.ssi_pid == qemu_pid) break; // QEMU terminated
                else if (info.ssi_pid == virtiofsd_pid) {
                    std::cout << "virtiofsd terminated!" << std::endl;
                }
             }
        }
    }
    close(sigfd);

    int qemu_wstatus;
    waitpid(qemu_pid, &qemu_wstatus, 0);
    if (!WIFEXITED(qemu_wstatus)) throw std::runtime_error("QEMU terminated abnoamally.");
    std::cout << "QEMU terminated." << std::endl;
    //else
    return WEXITSTATUS(qemu_wstatus);
}

static int run(const std::optional<std::filesystem::path>& system_file, const std::optional<std::filesystem::path>& data_file, 
    const std::optional<std::filesystem::path>& swap_file, const RunOptions& options)
{
    // virtiofs_path is required if system_file is not provided
    if (!system_file && !options.virtiofs_path) throw std::runtime_error("virtiofs_path is required if system_file is not provided");

    auto vmname = options.name.value_or((system_file? get_default_hostname(*system_file) : std::nullopt).value_or(generate_temporary_hostname()));

    qemu_os_resources os_resources;

    //lock VM
    auto vm_lock_fd = run_dir::lock_vm(vmname);
    if (vm_lock_fd < 0) throw std::runtime_error(vmname + " is already running");
    //else
    os_resources.vm_run_dir_lock_fd = vm_lock_fd;

    const auto [kernel, initramfs, arch] = extract_kernel_and_initramfs(system_file? *system_file : options.virtiofs_path.value());
    //std::cout << "Architecture: " << arch.value_or("Unknown") << std::endl;

    if (!arch.has_value()) throw std::runtime_error("Unsupported kernel format");

    std::string append = system_file? "root=/dev/vda ro" : "root=fs rootfstype=virtiofs rw"; // TODO: check fstab to determine ro/rw
    append += " net.ifnames=0 systemd.firstboot=0 systemd.hostname=" + vmname;
    if (options.hvc) {
        append += " console=hvc0";
    } else {
        if (arch == "aarch64" || arch->starts_with("arm")) {
            append += " console=ttyAMA0";
        } else {
            append += " console=ttyS0,115200n8r";
        }
    }
    if (options.append.has_value()) {
        append += ' ';
        append += options.append.value();
    }
    if (options.display && *options.display != "none") {
        append += " console=tty1";
    }
    std::vector<std::string> qemu_cmdline = {
        "qemu-system-" + arch.value(),
        "-kernel", kernel.string(), "-append", append
    };

    if (initramfs.has_value()) {
        qemu_cmdline.insert(qemu_cmdline.end(), {"-initrd", initramfs.value()});
    }

    apply_common_args_to_qemu_cmdline(vmname, qemu_cmdline);

    if (system_file) {
        qemu_cmdline.insert(qemu_cmdline.end(), {"-drive", "file=" + system_file->string() + ",format=raw,media=disk,if=virtio,readonly=on" 
            + (is_o_direct_supported(*system_file)? ",aio=native,cache.direct=on":"") });
    } else {
        // dummy data
        qemu_cmdline.insert(qemu_cmdline.end(), {"-drive", "file=" + create_dummy_block_file("system").string() + ",format=raw,readonly=on,media=disk,if=virtio,readonly=on"});
    }

    if (data_file) {
        qemu_cmdline.insert(qemu_cmdline.end(), {"-drive", "file=" + data_file->string() + ",format=raw,media=disk,if=virtio" 
            + (is_o_direct_supported(*data_file)? ",aio=native,cache.direct=on":"") });
    } else {
        // dummy data
        qemu_cmdline.insert(qemu_cmdline.end(), {"-drive", "file=" + create_dummy_block_file("data").string() + ",format=raw,readonly=on,media=disk,if=virtio,readonly=on"});
    }

    if (swap_file) {
        qemu_cmdline.insert(qemu_cmdline.end(), {"-drive", "file=" + swap_file->string() + ",format=raw,media=disk,if=virtio" 
            + (is_o_direct_supported(*swap_file)? ",aio=native,cache.direct=on":"") });
    } else {
        // dummy swap
        qemu_cmdline.insert(qemu_cmdline.end(), {"-drive", "file=" + create_dummy_block_file("swapfile").string() + ",format=raw,readonly=on,media=disk,if=virtio,readonly=on"});
    }

    auto guest_cid = apply_options_to_qemu_cmdline(vmname, qemu_cmdline, options, arch.value(), os_resources);

    // if VM uses PCI-passthrough, create iommu-mem file and write memory size to it
    bool iommu = options.pci.size() > 0 || std::any_of(options.net.begin(), options.net.end(), [](const auto& t) {
        return std::holds_alternative<netif::type::SRIOV>(std::get<0>(t));
    });
    if (iommu) {
        pci::acquire_iommu_memory(vmname, options.memory);
    }

    auto virtiofsd_pid = [&]() {
        if (!options.virtiofs_path.has_value()) return -1;
        //else
        std::cout << "Starting virtiofsd with " << options.virtiofs_path.value().string() << "..." << std::endl;
        auto pid = run_virtiofsd(vmname, options.virtiofs_path.value(), 
            {options.virtiofs_rlimit_nofile, options.virtiofs_cache, options.virtiofs_inode_file_handles});
        apply_virtiofs_to_qemu_cmdline(vmname, qemu_cmdline, pid);
        return pid;
    } ();

    if (virtiofsd_pid > 0) os_resources.virtiofsd_pid = virtiofsd_pid;

    std::cout << "Executing QEMU..." << std::endl;
    std::cout << "Guest CID: " << guest_cid << std::endl;
    std::cout << "`ssh -o ProxyCommand='socat STDIO vsock-connect:" << guest_cid << ":22' user@" << vmname << "` to login to the VM." << std::endl;
    return run_qemu(vmname, qemu_cmdline, options.qemu_env, virtiofsd_pid);
}

static int run_bios(const RunOptions& options)
{
    auto vmname = options.name.value_or(generate_temporary_hostname());

    qemu_os_resources os_resources;
    //lock VM
    auto vm_lock_fd = run_dir::lock_vm(vmname);
    if (vm_lock_fd < 0) throw std::runtime_error(vmname + " is already running");
    //else
    os_resources.vm_run_dir_lock_fd = vm_lock_fd;

    std::vector<std::string> qemu_cmdline = {
        "qemu-system-x86_64"
    };

    apply_common_args_to_qemu_cmdline(vmname, qemu_cmdline);
    apply_options_to_qemu_cmdline(vmname, qemu_cmdline, options, "x86_64", os_resources, true);
    if (options.cdrom.has_value()) {
        qemu_cmdline.insert(qemu_cmdline.end(), {"-boot", "once=d"});
    }

    auto virtiofsd_pid = [&]() {
        if (!options.virtiofs_path.has_value()) return -1;
        //else
        std::cout << "Starting virtiofsd with " << options.virtiofs_path.value().string() << "..." << std::endl;
        auto pid = run_virtiofsd(vmname, options.virtiofs_path.value(), 
            {options.virtiofs_rlimit_nofile, options.virtiofs_cache, options.virtiofs_inode_file_handles});
        apply_virtiofs_to_qemu_cmdline(vmname, qemu_cmdline, pid);
        return pid;
    } ();

    if (virtiofsd_pid > 0) os_resources.virtiofsd_pid = virtiofsd_pid;

    std::cout << "Executing QEMU(BIOS)..." << std::endl;
    return run_qemu(vmname, qemu_cmdline, options.qemu_env, virtiofsd_pid);
}

static std::string escape_comma_for_qemu(const std::string& str)
{
    std::string ret;
    for (auto c:str) {
        if (c == ',') ret += ",,";
        else ret += c;
    }
    return ret;
}

static int service(const std::string& vmname, const std::filesystem::path& vm_dir, 
    std::optional<const std::string> default_net)
{
    if (vmname == "") throw std::runtime_error("VM name must not be empty.");
    if (!std::filesystem::exists(vm_dir)) throw std::runtime_error(vm_dir.string() + " does not exist.");
    if (!std::filesystem::is_directory(vm_dir)) throw std::runtime_error(vm_dir.string() + " is not a directory.");

    std::cout << "Starting " << vmname << " on " << vm_dir.string() << " ..." << std::endl;

    auto system_file = [&vm_dir]() {
        auto system_file_name = vm_dir / "system";
        return std::filesystem::exists(system_file_name)? std::make_optional(system_file_name) : std::nullopt;
    }();
    auto data_file = std::make_optional(vm_dir / "data");
    if (!std::filesystem::exists(data_file.value())) data_file = std::nullopt;
    auto swap_file = std::make_optional(vm_dir / "swapfile");
    if (!std::filesystem::exists(swap_file.value())) swap_file = std::nullopt;

    auto virtiofs_path = vm_dir / "fs";
    std::filesystem::create_directories(virtiofs_path);

    auto ini_path = vm_dir / "vm.ini";
    auto ini = std::shared_ptr<dictionary>(std::filesystem::exists(ini_path)? iniparser_load(ini_path.c_str()) : dictionary_new(0), iniparser_freedict);

    uint32_t memory = iniparser_getint(ini.get(), ":memory", default_memory_size);
    if (memory < 256) throw std::runtime_error("Memory too less");
    uint16_t cpus = iniparser_getint(ini.get(), ":cpu", 1);
    if (cpus < 1) throw std::runtime_error("Invalid cpu number");

    std::string type = iniparser_getstring(ini.get(), ":type", "genpack");

    std::vector<std::tuple<netif::type::Some,std::optional<std::string>,bool>> net;
    std::vector<std::string> hostfwd;
    bool has_user_net = false;
    for (int i = 0; i < 10; i++) {
        auto section = "net" + std::to_string(i);
        if (iniparser_find_entry(ini.get(), section.c_str()) == 0) continue; // no corresponding section
        auto interface = iniparser_getstring(ini.get(), (section + ":interface").c_str(), NULL);
        if (!interface) interface = iniparser_getstring(ini.get(), (section + ":bridge").c_str(), NULL); // backward compatibility
        if (!interface && i == 0 && default_net) interface = default_net->c_str();
        auto mac = iniparser_getstring(ini.get(), (section + ":mac").c_str(), NULL);
        bool vhost = (bool)iniparser_getboolean(ini.get(), (section + ":vhost").c_str(), 1);

        if (!interface) 
            throw std::runtime_error("Interface for net" + std::to_string(i) + " must be specified.");
        //else

        auto netif_v = netif::to_netif(interface);
        if (std::holds_alternative<netif::type::User>(netif_v)) {
            if (has_user_net) throw std::runtime_error("Only one user network interface is allowed");
            //else
            has_user_net = true;

            auto hostfwd_cstr = iniparser_getstring(ini.get(), (section + ":hostfwd").c_str(), NULL);
            if (hostfwd_cstr) {
                std::string hostfwd_str = hostfwd_cstr;
                std::string::size_type pos = 0;
                while ((pos = hostfwd_str.find(',')) != std::string::npos) {
                    auto fwd = hostfwd_str.substr(0, pos);
                    if (fwd.find(':') == std::string::npos) throw std::runtime_error("Invalid hostfwd format");
                    //else
                    hostfwd.push_back(fwd);
                    hostfwd_str.erase(0, pos + 1);
                }
                if (hostfwd_str.find(':') == std::string::npos) throw std::runtime_error("Invalid hostfwd format");
                //else
                hostfwd.push_back(hostfwd_str);
            }
        }

        net.push_back({
            netif_v, 
            mac? std::make_optional(std::string(mac)) : std::nullopt, 
            vhost
        });
    }

    if (net.size() == 0) {
        if (default_net) { // if no net section and default bridge given, add default netif
            net.push_back({netif::to_netif(*default_net), std::nullopt, true});
        } else {
            net.push_back({netif::type::User(), std::nullopt, true});
        }
    }

    auto usb_query = iniparser_getstring(ini.get(), ":usb", NULL);
    // query USB devices using XPath
    std::vector<std::filesystem::path> usb = usb_query? query_usb_devices(usb_query) : std::vector<std::filesystem::path>();

    // scan USB devices
    // scan symlink to /dev/bus/usb/xxx/yyy
    for (int i = 0; i < 10; i++) {
        auto device = vm_dir / ("usb" + std::to_string(i));
        if (std::filesystem::exists(device) && std::filesystem::is_character_file(device)) {
            usb.push_back(device);
        }
    }

    auto append = iniparser_getstring(ini.get(), ":append", NULL);
    auto display = iniparser_getstring(ini.get(), ":display", NULL);
    auto spice = iniparser_getstring(ini.get(), ":spice", NULL);
    auto vnc = iniparser_getstring(ini.get(), ":vnc", NULL);
    auto accel = RunOptions::to_accel(iniparser_getstring(ini.get(), ":accel", "2d"));
    auto gpu_max_outputs = (uint16_t)iniparser_getint(ini.get(), ":gpu_max_outputs", 1);
    auto rendernode = iniparser_getstring(ini.get(), ":rendernode", NULL);

    std::vector<std::pair<std::filesystem::path,bool>> disks;
    for (int i = 0; i < 10; i++) {
        auto disk_name = "disk" + std::to_string(i);
        auto disk = vm_dir / disk_name;
        char buf[16];
        sprintf(buf, "disk%d:virtio", i);
        auto virtio = iniparser_getboolean(ini.get(), buf, true);
        if (std::filesystem::exists(disk)) disks.push_back({disk,virtio});
    }
   
    // PCI passthrough
    std::vector<std::string> pci;
    for (int i = 0; i < 10; i++) {
        char buf[16];
        sprintf(buf, "pci%d", i);
        if (iniparser_find_entry(ini.get(), buf) == 0) continue;
        sprintf(buf, "pci%d:id", i);
        auto pci_id = iniparser_getstring(ini.get(), buf, NULL);
        if (!pci_id) throw std::runtime_error("id is not specified for pci" + std::to_string(i));
        //else
        pci.push_back(pci_id);
    }

    auto cdrom = 
        std::filesystem::exists(vm_dir / "cdrom")? std::make_optional(vm_dir / "cdrom") : std::nullopt;
    
    std::map<std::string,std::string> firmware_strings;
    auto firmware_keys_len = iniparser_getsecnkeys(ini.get(), "firmware-string");
    if (firmware_keys_len > 0) {
        const char** firmware_keys = (const char**)malloc(sizeof(const char*) * firmware_keys_len);
        if (iniparser_getseckeys(ini.get(), "firmware-string", firmware_keys) != NULL) {
            for (int i = 0; i < firmware_keys_len; i++) {
                const char* key = firmware_keys[i];
                std::string value = iniparser_getstring(ini.get(), key, "");
                firmware_strings[key + 16/*firmware-string:*/] = escape_comma_for_qemu(value);
            }
        }
        free(firmware_keys);
    }

    auto application_ini = generate_application_ini_file(ini.get());
    std::map<std::string,std::filesystem::path> firmware_files;
    if (application_ini.has_value()) {
        firmware_files["application.ini"] = application_ini.value();
    }

    // qemu env
    std::map<std::string,std::string> qemu_env;
    const char* wayland_display = iniparser_getstring(ini.get(), ":wayland-display", NULL);
    if (wayland_display) qemu_env["WAYLAND_DISPLAY"] = wayland_display;
    const char* x11_display = iniparser_getstring(ini.get(), ":x11-display", NULL);
    if (x11_display) qemu_env["X11_DISPLAY"] = x11_display;

    // virtiofs options
    long int rlimit_nofile = iniparser_getlongint(ini.get(), "virtiofs:rlimit-nofile", 0);
    const char* virtiofs_cache = iniparser_getstring(ini.get(), "virtiofs:cache", NULL);
    const char* virtiofs_inode_file_handles = iniparser_getstring(ini.get(), "virtiofs:inode-file-handles", NULL);

    if (type == "genpack") {
        return run(system_file, data_file, swap_file, {
                .name = vmname,
                .virtiofs_path = virtiofs_path,
                .memory = memory,
                .cpus = cpus,
                .net = net,
                .hostfwd = hostfwd,
                .usb = usb,
                .disks = disks,
                .pci = pci,
                .cdrom = cdrom,
                .append = append? std::make_optional(append) : std::nullopt,
                .display = display? std::make_optional(display) : std::nullopt,
                .spice = spice? std::make_optional(spice) : std::nullopt,
                .accel = accel,
                .gpu_max_outputs = gpu_max_outputs,
                .rendernode = rendernode? std::make_optional(rendernode) : std::nullopt,
                .stdio_console = false,
                .firmware_strings = firmware_strings,
                .firmware_files = firmware_files,
                .qemu_env = qemu_env,
                .virtiofs_rlimit_nofile = rlimit_nofile > 0? std::optional(rlimit_nofile) : std::nullopt,
                .virtiofs_cache = virtiofs_cache? std::make_optional(std::string(virtiofs_cache)) : std::nullopt,
                .virtiofs_inode_file_handles = virtiofs_inode_file_handles? std::make_optional(std::string(virtiofs_inode_file_handles)) : std::nullopt
            } );
    } else if (type == "bios") {
        return run_bios({
                .name = vmname,
                .virtiofs_path = virtiofs_path,
                .memory = memory,
                .cpus = cpus,
                .net = net,
                .hostfwd = hostfwd,
                .usb = usb,
                .disks = disks,
                .pci = pci,
                .cdrom = cdrom,
                .display = display? std::make_optional(display) : std::nullopt,
                .spice = spice? std::make_optional(spice) : std::nullopt,
                .accel = accel,
                .gpu_max_outputs = gpu_max_outputs,
                .rendernode = rendernode? std::make_optional(rendernode) : std::nullopt,
                .stdio_console = false,
                .firmware_strings = firmware_strings,
                .firmware_files = firmware_files,
                .qemu_env = qemu_env,
                .virtiofs_rlimit_nofile = rlimit_nofile > 0? std::optional(rlimit_nofile) : std::nullopt,
                .virtiofs_cache = virtiofs_cache? std::make_optional(std::string(virtiofs_cache)) : std::nullopt,
                .virtiofs_inode_file_handles = virtiofs_inode_file_handles? std::make_optional(std::string(virtiofs_inode_file_handles)) : std::nullopt
            } );
    } else {
        throw std::runtime_error("Unknown VM type '" + type + "'.");
    }
}

static int console(const std::string& vmname)
{
    auto sock = sock_connect(run_dir::console_sock(vmname));
    if (sock < 0) throw std::runtime_error("No console port for VM " + vmname + ".");

    Finally<int> sock_close([](int sock) {
        close(sock);
    }, sock);

    static struct termios old_term;
    if (tcgetattr(STDIN_FILENO, &old_term) < 0) throw std::runtime_error("tcgetattr() failed.");

    struct termios new_term;
    memcpy(&new_term, &old_term, sizeof(new_term));
    cfmakeraw(&new_term);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);
    Finally<const struct termios&> back_to_old_terminal([](const struct termios& old_term) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    }, old_term);

    while(true) {
        struct pollfd pollfds[2];
        pollfds[0].fd = sock;
        pollfds[0].events = POLLIN;
        pollfds[1].fd = STDIN_FILENO;
        pollfds[1].events = POLLIN;

        poll(pollfds, 2, 1000);

        char buf[4096];

        if (pollfds[0].revents & POLLIN) {
            auto r = read(sock, buf, sizeof(buf));
            if (r == 0) { // EOF
                break;
            }
            //else
            write(STDOUT_FILENO, buf, r);
        }

        if (pollfds[1].revents & POLLIN) {
            auto r = read(STDIN_FILENO, buf, sizeof(buf));
            if (r == 0) { // EOF
                break;
            }
            //else
            for (int i = 0; i < r; i++) {
                if (buf[i] == 29/*C-]*/) return 0;
                write(sock, &buf[i], 1);
            }
        }

    }
    return 0;
}

static std::optional<std::pair<uint64_t,uint64_t>> get_process_stat(pid_t pid)
{
    std::ifstream stat(std::filesystem::path("/proc") / std::to_string(pid) / "stat");
    if (!stat) return std::nullopt;

    std::string drop;
    stat >> drop; // drop pid;
    if (drop == "") return std::nullopt;
    char charval;
    stat >> charval;
    if (charval != '(') return std::nullopt; // 2nd value must starts with '('
    while (charval != ')') {
        if (stat.eof()) return std::nullopt; // '(' without ')'
        stat >> charval;
    }

	uint64_t utime,starttime;
    stat >> std::skipws >> drop >> drop >> drop >> drop >> drop >> drop >> drop 
        >> drop/*minflt*/ >> drop/*cminflt*/ >> drop/*majflt*/ >> drop/*cmajflt*/ 
        >> utime >> drop/*stime*/ >> drop/*cutime*/ >> drop/*cstime*/>> drop >> drop
        >> drop/*thread_nr*/ >> drop 
        >> starttime;

    struct sysinfo s_info;
    if (sysinfo(&s_info) < 0) return std::nullopt;
    uint64_t system_uptime_ms = s_info.uptime * 1000;
    uint64_t starttime_ms = starttime * 1000 / sysconf(_SC_CLK_TCK);
    uint64_t utime_ms = utime * 1000 / sysconf(_SC_CLK_TCK);
    uint64_t uptime_ms = system_uptime_ms - starttime_ms;

    return std::make_pair(uptime_ms, utime_ms);
}

static std::optional<std::tuple<
        std::string/*vmname*/,uint64_t/*memory*/,uint16_t/*cpus*/,uint64_t/*uptime_ms*/,uint64_t/*utime_ms*/>
    > check_running_vm(const std::string& vmname)
{
    auto qmp_sock = qmp_connect(vmname);
    if (qmp_sock < 0) return std::nullopt;

    receive_message(qmp_sock); // drop greeting message
    nlohmann::json capabilities_req;
    capabilities_req["execute"] = "qmp_capabilities";
    execute_query(qmp_sock, capabilities_req);
    nlohmann::json memory_size_summary_req;
    memory_size_summary_req["execute"] = "query-memory-size-summary";
    auto memory_size_summary = execute_query(qmp_sock, memory_size_summary_req);
    nlohmann::json cpus_req;
    cpus_req["execute"] = "query-cpus-fast";
    auto cpus = execute_query(qmp_sock, cpus_req);
    shutdown(qmp_sock, SHUT_WR);
    close(qmp_sock);
    uint64_t memory = memory_size_summary.has_value()? memory_size_summary.value()["return"]["base-memory"].get<uint64_t>() : 0;
    uint16_t ncpus = cpus.has_value()? cpus.value()["return"].size() : 0;

    pid_t pid = -1;
    uint64_t uptime_ms = 0, utime_ms = 0;
    std::ifstream(run_dir::qemu_pid(vmname)) >> pid;
    if (pid > 0) {
        auto process_stat = get_process_stat(pid);
        if (process_stat.has_value()) {
            auto [_1, _2] = process_stat.value();
            uptime_ms = _1;
            utime_ms = _2;
        }
    }

    return std::make_tuple(vmname, memory, ncpus, uptime_ms, utime_ms);
}

static std::vector<std::tuple<std::string,uint64_t,uint16_t,uint64_t,uint64_t>> collect_running_vm_info()
{
    using thread = std::future<std::optional<std::tuple<std::string,uint64_t,uint16_t,uint64_t,uint64_t>>>;
    auto threads = run_dir::for_each_running_vms<thread>([](const std::string& vmname) {
        return std::async(check_running_vm, vmname);
    });

    std::vector<std::tuple<std::string,uint64_t,uint16_t,uint64_t,uint64_t>> vms;
    for (auto& thread : threads) {
        auto vm = thread.get();
        if (vm.has_value()) vms.push_back(vm.value());
    }

    std::sort(vms.begin(), vms.end(), [](auto a, auto b) {
        return std::get<0>(a) < std::get<0>(b);
    });

    return vms;
}

static int show(std::optional<std::string> vmname)
{
    auto result = nlohmann::json::array();

    auto set_properties = [](nlohmann::json& obj, const std::string& vmname, uint64_t memory, uint16_t cpus,uint64_t uptime_ms,uint64_t utime_ms) {
        obj["name"] = vmname;
        obj["memory"] = memory;
        obj["cpus"] = cpus;
        obj["uptime_ms"] = uptime_ms;
        obj["utime_ms"] = utime_ms;
        obj["qmp"] = run_dir::qmp_sock(vmname);
        obj["monitor"] = run_dir::monitor_sock(vmname);
        if (std::filesystem::exists(run_dir::console_sock(vmname))) {
            obj["console"] = run_dir::console_sock(vmname);
        }
        obj["qemu-pid"] = run_dir::qemu_pid(vmname);
        obj["qga"] = run_dir::qga_sock(vmname);
    };

    if (vmname.has_value()) {
        auto vm = check_running_vm(vmname.value());
        if (vm.has_value()) {
            nlohmann::json entry;
            const auto& [vmname,memory,cpus,uptime_ms,utime_ms] = vm.value();
            set_properties(entry, vmname, memory, cpus, uptime_ms, utime_ms);
            result.push_back(entry);
        }
    } else {
        for (const auto& [vmname, memory, cpus, uptime_ms, utime_ms]:collect_running_vm_info()) {
            nlohmann::json entry;
            set_properties(entry, vmname, memory, cpus, uptime_ms, utime_ms);
            result.push_back(entry);
        }
    }

    std::cout << result << std::endl;
    return 0;
}

static std::string duration_str(uint64_t milliseconds)
{
    if (milliseconds == 0) return "-";
    uint64_t s = milliseconds / 1000;
    const auto [D,H,M] = std::make_tuple(24 * 60 * 60, 60 * 60, 60);
    int d = s / D;
    s -= d * D;
    int h = s / H;
    s -= h * H;
    int m = s / M;
    s -= m * M;
    std::string str;
    if (d > 0) str += std::to_string(d) + 'd';
    if (h > 0) str += std::to_string(h) + 'h';
    if (m > 0) str += std::to_string(m) + 'm';
    if (d == 0) {
        str += std::to_string(s) + 's';
    }
    return str;
}

static int list()
{
    const auto running_vms = collect_running_vm_info();
    if (running_vms.size() == 0) {
        std::cout << "No VMs are running." << std::endl;
        return 0;
    }
    // else
    std::shared_ptr<libscols_table> table(scols_new_table(), scols_unref_table);
    if (!table) throw std::runtime_error("scols_new_table() failed");
    scols_table_new_column(table.get(), "NAME", 0.1, 0);
    scols_table_new_column(table.get(), "MEMORY(MB)", 0.1, SCOLS_FL_RIGHT);
    scols_table_new_column(table.get(), "#CPU", 0.1, SCOLS_FL_RIGHT);
    scols_table_new_column(table.get(), "UPTIME", 0.1, SCOLS_FL_RIGHT);
    auto sep = scols_table_new_line(table.get(), NULL);
    scols_line_set_data(sep, 0, "-------------");
    scols_line_set_data(sep, 1, "----------");
    scols_line_set_data(sep, 2, "----");
    scols_line_set_data(sep, 3, "-----------");
    for (const auto& [vmname, memory, cpus, uptime_ms, utime_ms]:running_vms) {
        auto line = scols_table_new_line(table.get(), NULL);
        if (!line) throw std::runtime_error("scols_table_new_line() failed");
        scols_line_set_data(line, 0, vmname.c_str());
        scols_line_set_data(line, 1, std::to_string(memory / 1024 / 1024).c_str());
        scols_line_set_data(line, 2, std::to_string(cpus).c_str());
        scols_line_set_data(line, 3, duration_str(uptime_ms).c_str());
    }
    scols_print_table(table.get());
    return 0;
}

static int allocate(const std::filesystem::path& filename, uint32_t size)
{
    if (size < 1) throw std::runtime_error("Size must be larger than zero");
    auto fd = open(filename.c_str(), O_CREAT|O_RDWR, S_IRUSR|S_IWUSR);
    if (fd < 0) throw std::runtime_error("Creating file with open() failed. Error createing data file.");
    int f = 0;
    if (ioctl(fd, EXT2_IOC_GETFLAGS, &f) == 0 && !(f & FS_NOCOW_FL)) {
        f |= FS_NOCOW_FL;
        ioctl(fd, EXT2_IOC_SETFLAGS, &f);
    }
    close(fd);
    auto size_in_gib = size * 1024LL * 1024L * 1024L;
    if (std::filesystem::file_size(filename) > size_in_gib) throw std::runtime_error("Shrinking size is not allowed");
    //else
    fd = open(filename.c_str(), O_RDWR);
    if (fd < 0) throw std::runtime_error("open() failed. Error createing data file.");
    if (fallocate(fd, 0, 0, size_in_gib) < 0) {
        close(fd);
        throw std::runtime_error("fallocate() failed. Error createing data file. (err=" + std::string(strerror(errno)) + ")");
    }
    close(fd);
    return 0;
}

static int expand(const std::string& vmname)
{
    auto qmp_sock = qmp_connect(vmname);
    if (qmp_sock < 0) throw std::runtime_error("Unable to connect VM");

    Finally<int> qmp_sock_finally([](auto fd){
        shutdown(fd, SHUT_WR);
        close(fd);
    }, qmp_sock);

    receive_message(qmp_sock); // drop greeting message
    execute_query(qmp_sock, nlohmann::json({ {"execute", "qmp_capabilities"} }));
    auto blockdevices = execute_query(qmp_sock, nlohmann::json({ {"execute", "query-block"} }));
    if (!blockdevices || !blockdevices->contains("return")) throw std::runtime_error("Invalid response from VM");
    for (auto& blockdevice : blockdevices.value()["return"]) {
        if (blockdevice["removable"] != false || !blockdevice.contains("inserted")) continue;
        auto inserted = blockdevice["inserted"];
        if (inserted["ro"] != false || !inserted.contains("image")) continue;
        auto image = inserted["image"];
        if (image["format"] != "raw" || !image.contains("filename") || !image.contains("virtual-size")) continue;
        auto device = blockdevice["device"].get<std::string>();
        auto filename = image["filename"].get<std::filesystem::path>();
        auto size = image["virtual-size"] .get<uint64_t>();
        if (size < 1024L * 1024L) continue; // smaller than 1MB should be ignored
        std::uintmax_t newsize = 0;
        if (std::filesystem::exists(filename)) {
            if (std::filesystem::is_regular_file(filename)) {
                newsize = std::filesystem::file_size(filename);
            } else if (std::filesystem::is_block_file(filename)) {
                auto fd = open(filename.c_str(), O_RDONLY);
                if (fd >= 0) {
                    uint64_t blocksize;
                    if (ioctl(fd, BLKGETSIZE64, &blocksize) == 0) {
                        newsize = blocksize;
                    }
                    close(fd);
                }
            }
        }
        if (newsize < size) continue;
        //else
        auto rst = execute_query(qmp_sock, nlohmann::json({ {"execute", "block_resize"}, {"arguments", {{"device", device}, {"size", newsize}} } }));
        if (!rst || !rst->contains("return")) throw std::runtime_error("Failed to resize block device " + device + "(" + filename.string() + ")");
        //else 
        std::cout << device << "(" << filename << ") on " << vmname << " resized from " << size << " to " << newsize << "." << std::endl;
    }

    return 0;
}

static int _main(int argc, char* argv[])
{
    argparse::ArgumentParser program(argv[0]);

    argparse::ArgumentParser run_command("run");
    run_command.add_description("Run VM specifying system file");
    run_command.add_argument("-n", "--name").nargs(1);
    run_command.add_argument("-m", "--memory").default_value(default_memory_size).scan<'u',uint32_t>();
    run_command.add_argument("-c", "--cpu").default_value<uint16_t>(1).scan<'u',uint16_t>().help("Number of CPU cores");
    run_command.add_argument("--bios").default_value(false).implicit_value(true);
    run_command.add_argument("--no-virtio-for-bios-disks").default_value(false).implicit_value(true);
    run_command.add_argument("-d", "--data-file").nargs(1).help("Data file(or D drive image in BIOS mode)");
    run_command.add_argument("--volatile-data").default_value(false).implicit_value(true);
    run_command.add_argument("--cdrom").nargs(1);
    run_command.add_argument("-i", "--net").help("Network interface").append();
    run_command.add_argument("--hostfwd").help("pass hostfwd to QEMU").append();
    run_command.add_argument("--virtiofs-path").nargs(1);
    run_command.add_argument("--no-kvm").default_value(false).implicit_value(true);
    run_command.add_argument("--append").nargs(1);
    run_command.add_argument("--display").nargs(1);
    run_command.add_argument("--spice").nargs(1);
    run_command.add_argument("--vnc").nargs(1);
    run_command.add_argument("--accel").help("Graphics acceraration(2d|opengl|vulkan)").default_value(RunOptions::accel_t::_2d).action(RunOptions::to_accel);
    run_command.add_argument("--gpu-max-outputs").nargs(1).scan<'u',uint16_t>().default_value<uint16_t>(1);
    run_command.add_argument("--rendernode").nargs(1).help("DRM render node to pass to QEMU");
    run_command.add_argument("--hvc").default_value(false).implicit_value(true);
    run_command.add_argument("--pci").nargs(1);
    run_command.add_argument("--usb").nargs(1).help("XPath query to specify USB devices to passthrough");
    run_command.add_argument("--no-shutdown").default_value(false).implicit_value(true);
    run_command.add_argument("system_file").nargs(1).help("System file (or C drive image in BIOS mode)");
    run_command.add_argument("--application-ini").nargs(1).help("application.ini file to pass to VM");
    run_command.add_argument("--logging-items").nargs(1).help("Logging items to pass to QEMU");
    run_command.add_argument("--trace").nargs(1).help("Tracing options for QEMU");
    run_command.add_argument("--logfile").nargs(1).help("Log file to output instead of stderr");
    run_command.add_argument("--9p").nargs(1).help("Directory to share with guest via 9pfs");
    program.add_subparser(run_command);

    argparse::ArgumentParser service_command("service");
    service_command.add_description("Run VM as systemd service");
    service_command.add_argument("-i", "--default-net").nargs(1).help("Nwtrosk interface when network is not explicitly specified");
    service_command.add_argument("-b").nargs(1).help("Synonym for --default-net");
    service_command.add_argument("-n", "--name").nargs(1);
    service_command.add_argument("vm-dir").nargs(1);
    program.add_subparser(service_command);

    argparse::ArgumentParser console_command("console");
    console_command.add_description("Connect to VM console");
    console_command.add_argument("vmname").nargs(1);
    program.add_subparser(console_command);

    argparse::ArgumentParser stop_command("stop");
    stop_command.add_description("Stop VM");
    stop_command.add_argument("-c", "--console").default_value(false).implicit_value(true);
    stop_command.add_argument("-f", "--force").default_value(false).implicit_value(true);
    stop_command.add_argument("vmname").nargs(1);
    program.add_subparser(stop_command);

    argparse::ArgumentParser stopall_command("stopall");
    stopall_command.add_description("Stop all VMs");
    stopall_command.add_argument("-w", "--wait").default_value(false).implicit_value(true);
    stopall_command.add_argument("-f", "--force").default_value(false).implicit_value(true);
    program.add_subparser(stopall_command);

    argparse::ArgumentParser show_command("show");
    show_command.add_argument("vmname").nargs(argparse::nargs_pattern::optional);
    program.add_subparser(show_command);

    argparse::ArgumentParser list_command("list");
    program.add_subparser(list_command);

    argparse::ArgumentParser allocate_command("allocate");
    allocate_command.add_argument("filename").nargs(1);
    allocate_command.add_argument("size").nargs(1).scan<'u',uint32_t>().help("Size in GiB");
    program.add_subparser(allocate_command);

    argparse::ArgumentParser expand_command("expand");
    expand_command.add_argument("vmname").nargs(1);
    program.add_subparser(expand_command);

    argparse::ArgumentParser usb_command("usb");
    usb_command.add_description("USB device management");
    program.add_subparser(usb_command);
    usb_command.add_argument("-q", "--query").help("XPath query to test finding USB devices");

    argparse::ArgumentParser cid_command("cid");
    cid_command.add_description("Get CID from VM name");
    cid_command.add_argument("vmname").nargs(1);
    program.add_subparser(cid_command);

    try {
        program.parse_args(argc, argv);
    }
    catch (const std::runtime_error& err) {
        std::cerr << err.what() << std::endl;
        if (program.is_subcommand_used("run")) {
            std::cerr << run_command;
        } else if (program.is_subcommand_used("service")) {
            std::cerr << service_command;
        } else if (program.is_subcommand_used("console")) {
            std::cerr << console_command;
        } else if (program.is_subcommand_used("stop")) {
            std::cerr << stop_command;
        } else if (program.is_subcommand_used("stopall")) {
            std::cerr << stopall_command;
        } else if (program.is_subcommand_used("show")) {
            std::cerr << show_command;
        } else if (program.is_subcommand_used("list")) {
            std::cerr << list_command;
        } else if (program.is_subcommand_used("allocate")) {
            std::cerr << allocate_command;
        } else if (program.is_subcommand_used("expand")) {
            std::cerr << expand_command;
        } else if (program.is_subcommand_used("usb")) {
            std::cerr << usb_command;
        } else if (program.is_subcommand_used("cid")) {
            std::cerr << cid_command;
        } else {
            std::cerr << program;
        }
        return 1;
    }
    catch (const std::invalid_argument& err) {
        std::cerr << err.what() << std::endl;
        return 1;
    }

    if (program.is_subcommand_used("run")) {
        const auto system_file = run_command.get("system_file");
        auto volatile_data = run_command.get<bool>("--volatile-data");
        const auto data_file = run_command.present("-d");
        if (volatile_data && data_file.has_value()) {
            throw std::runtime_error("--volatile-data and --data-file(-d) are exclusive.");
        }
        auto virtiofs_path = run_command.present<std::string>("--virtiofs-path");
        auto p9_path = run_command.present<std::string>("--9p");
        if (!std::filesystem::exists(system_file)) throw std::runtime_error(system_file + " does not exist.");

        std::vector<std::tuple<netif::type::Some,std::optional<std::string>,bool>> net;
        for (const auto& i:run_command.get<std::vector<std::string>>("-i")) {
            net.push_back({netif::to_netif(i), std::nullopt/*generate mac address automatically*/, true});
        }
        if (net.size() == 0) {
            // if no --net given, add default netif
            net.push_back({netif::type::User(), std::nullopt, true});
        }

        auto hostfwd = run_command.get<std::vector<std::string>>("--hostfwd");

        std::vector<std::filesystem::path> usb = run_command.present("--usb")?
            query_usb_devices(run_command.get<std::string>("--usb")) : std::vector<std::filesystem::path>();

        auto real_data_file = (volatile_data || data_file.has_value())? 
                    std::make_optional(volatile_data? create_temporary_data_file() : std::filesystem::path(data_file.value()))
                    : std::nullopt;
        
        auto pci = run_command.get<std::vector<std::string>>("--pci");
        auto application_ini = run_command.present("--application-ini");
        std::map<std::string,std::filesystem::path> firmware_files;
        if (application_ini.has_value()) {
            firmware_files["application.ini"] = application_ini.value();
        }

        if (run_command.get<bool>("--bios")) {
            auto virtio = !run_command.get<bool>("--no-virtio-for-bios-disks");
            std::vector<std::pair<std::filesystem::path,bool>> disks = {{system_file, virtio}};
            if (real_data_file.has_value()) disks.push_back({real_data_file.value(), virtio});
            return run_bios({
                    .name = run_command.present("-n"),
                    .virtiofs_path = run_command.present("--virtiofs-path"),
                    .p9_path = p9_path,
                    .memory = run_command.get<uint32_t>("-m"),
                    .cpus = run_command.get<uint16_t>("-c"),
                    .kvm = run_command.get<bool>("--no-kvm")? std::make_optional(false) : std::nullopt,
                    .net = net,
                    .hostfwd = hostfwd,
                    .usb = usb,
                    .disks = disks,
                    .pci = pci,
                    .cdrom = run_command.present("--cdrom"),
                    .display = run_command.present("--display"),
                    .spice = run_command.present("--spice"),
                    .vnc = run_command.present("--vnc"),
                    .accel = run_command.get<RunOptions::accel_t>("--accel"),
                    .gpu_max_outputs = run_command.get<uint16_t>("--gpu-max-outputs"),
                    .rendernode = run_command.present("--rendernode"),
                    .hvc = run_command.get<bool>("--hvc"),
                    .stdio_console = true,
                    .no_shutdown = run_command.get<bool>("--no-shutdown"),
                    .firmware_files = firmware_files,
                    .logging_items = run_command.present("--logging-items"),
                    .trace = run_command.present("--trace"),
                    .logfile = run_command.present("--logfile")
                } );
        }
        // else 
        return run(system_file, real_data_file, std::nullopt, {
                .name = run_command.present("-n"),
                .virtiofs_path = run_command.present("--virtiofs-path"),
                .p9_path = p9_path,
                .memory = run_command.get<uint32_t>("-m"),
                .cpus = run_command.get<uint16_t>("-c"),
                .kvm = run_command.get<bool>("--no-kvm")? std::make_optional(false) : std::nullopt,
                .net = net,
                .hostfwd = hostfwd,
                .usb = usb,
                .pci = pci,
                .cdrom = run_command.present("--cdrom"),
                .append = run_command.present("--append"),
                .display = run_command.present("--display"),
                .spice = run_command.present("--spice"),
                .vnc = run_command.present("--vnc"),
                .accel = run_command.get<RunOptions::accel_t>("--accel"),
                .gpu_max_outputs = run_command.get<uint16_t>("--gpu-max-outputs"),
                .rendernode = run_command.present("--rendernode"),
                .hvc = run_command.get<bool>("--hvc"),
                .stdio_console = true,
                .no_shutdown = run_command.get<bool>("--no-shutdown"),
                .firmware_files = firmware_files,
                .logging_items = run_command.present("--logging-items"),
                .trace = run_command.present("--trace"),
                .logfile = run_command.present("--logfile")
            } );
    }

    if (program.is_subcommand_used("service")) {
        const std::filesystem::path vm_dir = service_command.get("vm-dir");
        const std::optional<std::string> vmname = service_command.present("--name");
        auto default_net = service_command.present("--default-net");
        if (!default_net) default_net = service_command.present("-b"); // for backward compatibility

        return service(
            vmname.value_or(std::filesystem::canonical(vm_dir).filename().string()),
            vm_dir, default_net);
    }

    if (program.is_subcommand_used("console")) {
        return console(console_command.get("vmname"));
    }

    if (program.is_subcommand_used("stop")) {
        auto vmname = stop_command.get("vmname");
        bool force = stop_command.get<bool>("-f");

        if (!qmp_shutdown(vmname, force)) throw std::runtime_error("Shutting down " + vmname + " failed.(not running?)");
        //else
        if (!force && stop_command.get<bool>("-c")) return console(vmname);
        //else
        return 0;
    }

    if (program.is_subcommand_used("stopall")) {
        bool force = stopall_command.get<bool>("-f");

        int rst = 0;
        std::set<std::string> vms_to_be_stopped;
        for (const auto& vm:collect_running_vm_info()) {
            const auto& vmname = std::get<0>(vm);
            std::cout << (force? "Force shutting" : "Shutting") << " down " << vmname << "..." << std::endl;
            if (!qmp_shutdown(vmname, force)) {
                std::cerr << "Shutting down " << vmname << " failed." << std::endl;
                rst = 1;
            }
            vms_to_be_stopped.insert(vmname);
        }
        if (stopall_command.get<bool>("-w") && vms_to_be_stopped.size() > 0) {
            while (true) {
                std::vector<std::string> vms(vms_to_be_stopped.begin(), vms_to_be_stopped.end());
                for (const auto& vmname:vms) {
                    if (!qmp_ping(vmname)) vms_to_be_stopped.erase(vmname);
                }
                int num = vms_to_be_stopped.size();
                if (num == 0) {
                    break;
                } else if (num == 1) {
                    std::cout << "Waiting for " << (*vms_to_be_stopped.begin()) << " to stop..." << std::endl;
                } else {
                    std::cout << "Waiting for " << num << " VMs to stop..." << std::endl;
                }
                sleep(1);
            }
            std::cout << "Stopped." << std::endl;
        }
        return rst;
    }

    if (program.is_subcommand_used("show")) {
        auto vmname = show_command.present("vmname");
        return show(vmname);
    }

    if (program.is_subcommand_used("list")) {
        return list();
    }

    if (program.is_subcommand_used("allocate")) {
        auto filename = allocate_command.get("filename");
        auto size = allocate_command.get<uint32_t>("size");
        return allocate(filename, size);
    }

    if (program.is_subcommand_used("expand")) {
        auto vmname = expand_command.get("vmname");
        return expand(vmname);
    }

    if (program.is_subcommand_used("usb")) {
        auto query = usb_command.present("--query");
        if (query) {
            auto devices = query_usb_devices(*query);
            for (const auto& device:devices) {
                std::cout << device.string() << std::endl;
            }
            if (devices.size() == 0) {
                std::cout << "No USB devices found." << std::endl;
            }
            return 0;
        }
        //else
        print_usb_devices_xml();
        print_example_query();
        return 0;
    }

    if (program.is_subcommand_used("cid")) {
        auto vmname = cid_command.get("vmname");
        auto cid = vsock::determine_guest_cid(vmname);
        std::cout << cid << std::endl;
        return 0;
    }

    std::cout << program;
    return 1;
}

#ifdef __VSCODE_ACTIVE_FILE__
int main(int argc, char* argv[])
{
    std::vector<std::string> args = { 
        argv[0], "list"
    };
    auto new_argv = (char**)malloc(sizeof(char*) * args.size());
    int new_argc = 0;
    for (auto arg:args) {
        auto c_arg = (char *)malloc(arg.length() + 1);
        strcpy(c_arg, arg.c_str());
        new_argv[new_argc++] = c_arg;
    }
    return _main(new_argc, new_argv);
}
#endif

#ifdef __USE_REAL_MAIN__
int main(int argc, char* argv[])
{
    try {
        return _main(argc, argv);
    }
    catch (const std::runtime_error& err) {
        std::cerr << err.what() << std::endl;
        return 1;
    }
}
#endif
