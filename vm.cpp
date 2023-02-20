#include <iostream>
#include <fstream>
#include <filesystem>
#include <optional>
#include <vector>
#include <cassert>
#include <future>
#include <set>

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
#include <linux/fs.h>
#include <ext2fs/ext2_fs.h>

#include <openssl/md5.h>
#include <libsmartcols/libsmartcols.h>
#include <systemd/sd-daemon.h>
#include <argparse/argparse.hpp>
#include <iniparser4/iniparser.h>

#include "json_messaging.h"

static const uint32_t default_memory_size = 2048;

template <typename T>
class Finally {
    std::function<void(const T&)> func;
    const T& arg;
public:
    Finally(std::function<void(const T&)> _func, const T& _arg) : func(_func), arg(_arg) {}
    ~Finally() { func(arg); }
};

static bool is_root_user()
{
    return (getuid() == 0);
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

static std::pair<std::filesystem::path,std::optional<std::filesystem::path>> 
    extract_kernel_and_initramfs(const std::filesystem::path& system_file)
{
    auto kernel_fd = memfd_create("kernel", 0);
    auto initramfs_fd = memfd_create("initramfs", 0);
    auto kernel_pid = fork();
    if (kernel_pid < 0) throw std::runtime_error("fork() failed");
    //else
    if (kernel_pid == 0) {
        close(STDOUT_FILENO);
        dup2(kernel_fd, STDOUT_FILENO);
        _exit(execlp("unsquashfs", "unsquashfs", "-q", "-cat", system_file.c_str(), "boot/kernel", NULL));
    }
    auto initramfs_pid = fork();
    if (initramfs_pid < 0) throw std::runtime_error("fork() failed");
    //else
    if (initramfs_pid == 0) {
        close(STDOUT_FILENO);
        dup2(initramfs_fd, STDOUT_FILENO);
        _exit(execlp("unsquashfs", "unsquashfs", "-q", "-cat", system_file.c_str(), "boot/initramfs", NULL));
    }
    int kernel_wstatus, initramfs_wstatus;
    waitpid(kernel_pid, &kernel_wstatus, 0);
    waitpid(initramfs_pid, &initramfs_wstatus, 0);
    if (!WIFEXITED(kernel_wstatus) || WEXITSTATUS(kernel_wstatus) != 0) 
        throw std::runtime_error("kernel extraction failed");
    if (!WIFEXITED(initramfs_wstatus) || WEXITSTATUS(initramfs_wstatus) != 0) {
        close(initramfs_fd);
        initramfs_fd = -1;
    }

    std::filesystem::path my_proc_fd = std::filesystem::path("/proc") / std::to_string(getpid()) / "fd";

    return {
        get_proc_fd_path(kernel_fd),
        initramfs_fd >= 0? std::optional(get_proc_fd_path(initramfs_fd)) : std::nullopt
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

static const std::filesystem::path& run_dir()
{
    static std::optional<std::filesystem::path> _run_dir = std::nullopt;
    if (!_run_dir.has_value()) {
        if (!is_root_user()) {
            const auto xdg_runtime_dir = getenv("XDG_RUNTIME_DIR");
             if (xdg_runtime_dir) _run_dir = (std::filesystem::path(xdg_runtime_dir) / "vm");
        }
        if (!_run_dir.has_value()) _run_dir = "/run/vm";
    }
    return _run_dir.value();
}

static std::filesystem::path vm_run_dir(const std::string& vmname)
{
    return run_dir() / vmname;
}

static auto qemu_pid(const std::string& vmname) {return vm_run_dir(vmname) / "qemu.pid";}
static auto qmp_sock(const std::string& vmname) {return vm_run_dir(vmname) / "qmp.sock";}
static auto monitor_sock(const std::string& vmname) {return vm_run_dir(vmname) / "monitor.sock";}
static auto console_sock(const std::string& vmname) {return vm_run_dir(vmname) / "console.sock";}
static auto qga_sock(const std::string& vmname) {return vm_run_dir(vmname) / "qga.sock";}
static auto virtiofs_sock(const std::string& vmname) {return vm_run_dir(vmname) / "virtiofs.sock";}

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

static auto qmp_connect(const std::string& vmname) {return sock_connect(qmp_sock(vmname));}

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
    const uint32_t memory = default_memory_size;
    const uint16_t cpus = 1;
    const std::optional<bool> kvm = std::nullopt;
    const std::vector<std::tuple<std::string/*bridge*/,std::optional<std::string>/*mac address*/,bool/*vhost*/>>& net = {};
    const std::vector<std::filesystem::path>& usb = {};
    const std::vector<std::pair<std::filesystem::path,bool/*virtio*/>>& disks = {};
    const std::vector<std::string>& pci = {};
    const std::optional<std::filesystem::path>& cdrom = std::nullopt;
    const std::optional<std::string>& append = std::nullopt;
    const std::optional<std::string>& display = std::nullopt;
    const bool hvc = false;
    const bool stdio_console = false;
    const bool no_shutdown = false;
    const std::map<std::string,std::string>& firmware_strings = {};
    const std::map<std::string,std::filesystem::path>& firmware_files = {};
    const std::map<std::string,std::string>& qemu_env = {};
};

static int lock_vm(const std::string& vmname)
{
    auto vm_run_dir_fd = open(vm_run_dir(vmname).c_str(), O_RDONLY, 0);
    if (vm_run_dir_fd < 0) throw std::runtime_error(std::string("open(") + vm_run_dir(vmname).string() + ") failed");

    if (flock(vm_run_dir_fd, LOCK_EX|LOCK_NB) < 0) {
        close(vm_run_dir_fd);
        if (errno == EWOULDBLOCK) return -1;
        else throw std::runtime_error(std::string("flock(") + vm_run_dir(vmname).string() + ") failed");
    }
    return vm_run_dir_fd;
}

static pid_t run_virtiofsd(const std::string& vmname, const std::filesystem::path& path)
{
    auto sock = virtiofs_sock(vmname);
    auto pid = fork();
    if (pid < 0) throw std::runtime_error("fork() failed");
    if (pid == 0) {
        _exit(execlp("/usr/libexec/virtiofsd", "/usr/libexec/virtiofsd", 
            "-f", "-o", ("cache=none,flock,posix_lock,xattr,allow_direct_io,source=" + path.string()).c_str(),
            ("--socket-path=" + sock.string()).c_str(),
            NULL));
    }
    //else
    // TODO: wait for socket to be ready
    return pid;
}

static std::optional<std::filesystem::path> generate_ssh_host_keys_archive(const std::string& vmname)
{
    auto ssh_host_key_root = vm_run_dir(vmname) / "ssh-host-key";
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
    std::vector<std::filesystem::path> ssh_public_key_candidates = {"id_ecdsa.pub", "id_rsa.pub"};
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
        "-monitor", "unix:" + monitor_sock(vmname).string() + ",server,nowait",
        "-qmp", "unix:" + qmp_sock(vmname).string() + ",server,nowait",
        "-chardev", "socket,path=" + qga_sock(vmname).string() + ",server=on,wait=off,id=qga0",
        "-device", "virtio-serial", "-device", "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0",
        "-fw_cfg", "opt/vmname,string=" + vmname,
        "-pidfile", qemu_pid(vmname)
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

static void apply_options_to_qemu_cmdline(const std::string& vmname, std::vector<std::string>& qemu_cmdline, const RunOptions& options, bool bios = false)
{
    // memory, display
    qemu_cmdline.insert(qemu_cmdline.end(), {
        "-m", std::to_string(options.memory),
        "-object", "memory-backend-memfd,id=mem,size=" + std::to_string(options.memory) + "M,share=on", "-numa", "node,memdev=mem",
        "-display", options.display.value_or("none")
    });

    // Console (Legacy serial, or HVC)
    if (options.hvc) {
        qemu_cmdline.insert(qemu_cmdline.end(), {
            "-device", "virtio-serial-pci", "-device", "virtconsole,chardev=hvc",
            "-chardev", (options.stdio_console? "stdio,signal=off,id=hvc" : "socket,path=" + console_sock(vmname).string() + ",server=on,wait=off,id=hvc")
        }); 
    } else {
        qemu_cmdline.insert(qemu_cmdline.end(), {
            "-serial",
            (options.stdio_console? "mon:stdio" : "unix:" + console_sock(vmname).string() + ",server=on,wait=off")
        });
    }
    // Number of CPU core
    if (options.cpus > 1) {
        qemu_cmdline.insert(qemu_cmdline.end(), {"-smp", "cpus=" + std::to_string(options.cpus)});
    }
    // Whether to use KVM
    if (options.kvm.value_or(access("/dev/kvm", R_OK|W_OK) == 0)) {
        qemu_cmdline.insert(qemu_cmdline.end(), {"-cpu", "host", "-enable-kvm"});
    }
    // Disks
    for (const auto& [disk,virtio] : options.disks) {
        qemu_cmdline.insert(qemu_cmdline.end(), {"-drive", "file=" + disk.string() + ",format=raw,media=disk"
            + (virtio? ",if=virtio" : "")
            + (!bios && is_o_direct_supported(disk)? ",aio=native,cache.direct=on":"") });
    }
    // Passthrough PCI devices
    for (const auto& pci : options.pci) {
        qemu_cmdline.push_back("-device");
        qemu_cmdline.push_back("vfio-pci,host=" + pci);
    }
    // Network interfaces
    int net_num = 0;
    for (const auto& [bridge,macaddr,vhost]:options.net) {
        auto generate_macaddr_from_name = [](const std::string& vmname, int num) {
            std::string name = vmname + ":" + std::to_string(num);
            unsigned char buf[16];
            MD5((const unsigned char*)name.c_str(), name.length(), buf);
            uint8_t mac[6] = { 0x52, 0x54, 0x00, 0x00, 0x00, 0x00 };
            mac[3] = buf[0] & 0x7f;
            mac[4] = buf[1];
            mac[5] = buf[2];
            char mac_str[18];
            sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", (int)mac[0], (int)mac[1], (int)mac[2], (int)mac[3], (int)mac[4], (int)mac[5]);
            return std::string(mac_str);
        };
        qemu_cmdline.insert(qemu_cmdline.end(), {
            "-netdev", "tap,id=net" + std::to_string(net_num) + ",br=" + bridge + ",helper=/usr/libexec/qemu-bridge-helper" + (vhost? ",vhost=on" : ""), 
            "-device", "virtio-net-pci,romfile=,netdev=net" + std::to_string(net_num) + ",mac=" + macaddr.value_or(generate_macaddr_from_name(vmname, net_num))});
        net_num++;
    }
    // USB devices
    if (options.usb.size() > 0) {
        qemu_cmdline.push_back("-usb");
        for (const auto& dev:options.usb) {
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

    // strings/files to be passed through fw_cfg
    for (const auto& [name,string]:options.firmware_strings) {
        if (name.find(',') != name.npos) throw std::runtime_error("Name cannot contain ','");
        qemu_cmdline.insert(qemu_cmdline.end(), {
            "-fw_cfg", "opt/" + name + ",string=" + string
        });
    }
    for (const auto& [name,file]:options.firmware_files) {
        if (name.find(',') != name.npos) throw std::runtime_error("Name cannot contain ','");
        qemu_cmdline.insert(qemu_cmdline.end(), {
            "-fw_cfg", "opt/" + name + ",file=" + file.string()
        });
    }

    if (options.no_shutdown) {
        qemu_cmdline.push_back("-no-shutdown");
    }
}

static void apply_virtiofs_to_qemu_cmdline(const std::string& vmname, std::vector<std::string>& qemu_cmdline, pid_t virtiofsd_pid)
{
    qemu_cmdline.insert(qemu_cmdline.end(), {
        "-chardev", "socket,id=virtiofs,path=" + virtiofs_sock(vmname).string(),
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

static int run(const std::filesystem::path& system_file, const std::optional<std::filesystem::path>& data_file, 
    const std::optional<std::filesystem::path>& swap_file, const RunOptions& options)
{
    auto vmname = options.name.value_or(get_default_hostname(system_file).value_or(generate_temporary_hostname()));
    std::filesystem::create_directories(vm_run_dir(vmname));

    //lock VM
    auto vm_lock_fd = lock_vm(vmname);
    if (vm_lock_fd < 0) throw std::runtime_error(vmname + " is already running");
    //else
    Finally<int> vm_run_dir_lock([](auto fd){
        flock(fd, LOCK_UN);
        close(fd);
    }, vm_lock_fd);

    const auto [kernel, initramfs] = extract_kernel_and_initramfs(system_file);

    std::string append = "root=/dev/vda ro net.ifnames=0 systemd.firstboot=0 systemd.hostname=" + vmname;
    if (options.hvc) {
        append += " console=hvc0";
    } else {
        append += " console=ttyS0,115200n8r";
    }
    if (options.append.has_value()) {
        append += ' ';
        append += options.append.value();
    }
    if (options.display && *options.display != "none") {
        append += " console=tty1";
    }
    std::vector<std::string> qemu_cmdline = {
        "qemu-system-x86_64", "-M","q35",
        "-kernel", kernel.string(), "-append", append,
        "-drive", "file=" + system_file.string() + ",format=raw,readonly=on,media=disk,if=virtio,aio=native,cache.direct=on"
    };


    if (initramfs.has_value()) {
        qemu_cmdline.insert(qemu_cmdline.end(), {"-initrd", initramfs.value()});
    }

    apply_common_args_to_qemu_cmdline(vmname, qemu_cmdline);

    if (data_file.has_value()) {
        auto _ = data_file.value();
        qemu_cmdline.insert(qemu_cmdline.end(), {"-drive", "file=" + _.string() + ",format=raw,media=disk,if=virtio" 
            + (is_o_direct_supported(_)? ",aio=native,cache.direct=on":"") });
    } else {
        // dummy data
        qemu_cmdline.insert(qemu_cmdline.end(), {"-drive", "file=" + create_dummy_block_file("data").string() + ",format=raw,readonly=on,media=disk,if=virtio"});
    }

    if (swap_file.has_value()) {
        auto _ = swap_file.value();
        qemu_cmdline.insert(qemu_cmdline.end(), {"-drive", "file=" + _.string() + ",format=raw,media=disk,if=virtio" 
            + (is_o_direct_supported(_)? ",aio=native,cache.direct=on":"") });
    } else {
        // dummy swap
        qemu_cmdline.insert(qemu_cmdline.end(), {"-drive", "file=" + create_dummy_block_file("swapfile").string() + ",format=raw,readonly=on,media=disk,if=virtio"});
    }

    apply_options_to_qemu_cmdline(vmname, qemu_cmdline, options);

    auto virtiofsd_pid = [&]() {
        if (!options.virtiofs_path.has_value()) return -1;
        //else
        std::cout << "Starting virtiofsd with " << options.virtiofs_path.value().string() << "..." << std::endl;
        auto pid = run_virtiofsd(vmname, options.virtiofs_path.value());
        apply_virtiofs_to_qemu_cmdline(vmname, qemu_cmdline, pid);
        return pid;
    } ();

    Finally<pid_t> virtiofsd([](auto pid) {
        if (pid < 0) return;
        //else
        std::cout << "Shutting down virtiofsd..." << std::endl;
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
    },  virtiofsd_pid);

    std::cout << "Executing QEMU..." << std::endl;
    return run_qemu(vmname, qemu_cmdline, options.qemu_env, virtiofsd_pid);
}

static int run_bios(const RunOptions& options)
{
    auto vmname = options.name.value_or(generate_temporary_hostname());
    std::filesystem::create_directories(vm_run_dir(vmname));

    //lock VM
    auto vm_lock_fd = lock_vm(vmname);
    if (vm_lock_fd < 0) throw std::runtime_error(vmname + " is already running");
    //else
    Finally<int> vm_run_dir_lock([](auto fd){
        flock(fd, LOCK_UN);
        close(fd);
    }, vm_lock_fd);

    std::vector<std::string> qemu_cmdline = {
        "qemu-system-x86_64", "-M","q35"
    };

    apply_common_args_to_qemu_cmdline(vmname, qemu_cmdline);
    apply_options_to_qemu_cmdline(vmname, qemu_cmdline, options, true);
    if (options.cdrom.has_value()) {
        qemu_cmdline.insert(qemu_cmdline.end(), {"-boot", "once=d"});
    }

    auto virtiofsd_pid = [&]() {
        if (!options.virtiofs_path.has_value()) return -1;
        //else
        std::cout << "Starting virtiofsd with " << options.virtiofs_path.value().string() << "..." << std::endl;
        auto pid = run_virtiofsd(vmname, options.virtiofs_path.value());
        apply_virtiofs_to_qemu_cmdline(vmname, qemu_cmdline, pid);
        return pid;
    } ();

    Finally<pid_t> virtiofsd([](auto pid) {
        if (pid < 0) return;
        //else
        std::cout << "Shutting down virtiofsd..." << std::endl;
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
    },  virtiofsd_pid);

    std::cout << "Executing QEMU(BIOS)..." << std::endl;
    return run_qemu(vmname, qemu_cmdline, options.qemu_env, virtiofsd_pid);
}

static int service(const std::string& vmname, const std::filesystem::path& vm_dir, std::optional<const std::string> bridge)
{
    if (vmname == "") throw std::runtime_error("VM name must not be empty.");
    if (!std::filesystem::exists(vm_dir)) throw std::runtime_error(vm_dir.string() + " does not exist.");
    if (!std::filesystem::is_directory(vm_dir)) throw std::runtime_error(vm_dir.string() + " is not a directory.");

    std::cout << "Starting " << vmname << " on " << vm_dir.string() << " ..." << std::endl;

    auto system_file = vm_dir / "system";
    auto data_file = std::make_optional(vm_dir / "data");
    if (!std::filesystem::exists(data_file.value())) data_file = std::nullopt;
    auto swap_file = std::make_optional(vm_dir / "swapfile");
    if (!std::filesystem::exists(swap_file.value())) swap_file = std::nullopt;

    auto virtiofs_path = is_root_user()? std::make_optional(vm_dir / "fs") : std::nullopt;
    if (virtiofs_path.has_value()) std::filesystem::create_directories(virtiofs_path.value());

    auto ini_path = vm_dir / "vm.ini";
    auto ini = std::shared_ptr<dictionary>(std::filesystem::exists(ini_path)? iniparser_load(ini_path.c_str()) : dictionary_new(0), iniparser_freedict);

    uint32_t memory = iniparser_getint(ini.get(), ":memory", default_memory_size);
    if (memory < 256) throw std::runtime_error("Memory too less");
    uint16_t cpus = iniparser_getint(ini.get(), ":cpu", 1);
    if (cpus < 1) throw std::runtime_error("Invalid cpu number");

    std::string type = iniparser_getstring(ini.get(), ":type", "genpack");

    std::vector<std::tuple<std::string,std::optional<std::string>,bool>> net;
    for (int i = 0; i < 10; i++) {
        char buf[16];
        sprintf(buf, "net%d", i);
        if (iniparser_find_entry(ini.get(), buf) == 0) continue;
        sprintf(buf, "net%d:bridge", i);
        auto bridge_str = iniparser_getstring(ini.get(), buf, NULL);
        sprintf(buf, "net%d:mac", i);
        auto mac = iniparser_getstring(ini.get(), buf, NULL);
        sprintf(buf, "net%d:vhost", i);
        bool vhost = (bool)iniparser_getboolean(ini.get(), buf, 1);

        if ((i > 0 || !bridge.has_value()) && !bridge_str) throw std::runtime_error("Bridge for net" + std::to_string(i) + " must be specified.");
        if (!bridge_str) bridge_str = bridge.value().c_str();
        net.push_back({bridge_str, mac? std::make_optional(std::string(mac)) : std::nullopt, vhost});
    }

    if (net.size() == 0 && bridge.has_value()) { // if no net section and default bridge given, add default netif
        net.push_back({bridge.value(), std::nullopt, true});
    }

    // scan USB devices
    std::vector<std::filesystem::path> usb;
    for (int i = 0; i < 10; i++) {
        auto device = vm_dir / ("usb" + std::to_string(i));
        if (std::filesystem::exists(device) && std::filesystem::is_character_file(device)) {
            usb.push_back(device);
        }
    }

    auto append = iniparser_getstring(ini.get(), ":append", NULL);
    auto display = iniparser_getstring(ini.get(), ":display", NULL);

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
    /*
        e.g.
        modprobe vfio-pci
        echo -n "0000:01:00.0" > /sys/bus/pci/drivers/amdgpu/unbind
        echo vfio-pci > /sys/bus/pci/devices/0000\:01\:00.0/driver_override
        echo 0000:01:00.0 > /sys/bus/pci/drivers_probe

        echo -n "0000:01:00.1" > /sys/bus/pci/drivers/snd_hda_intel/unbind
        echo vfio-pci > /sys/bus/pci/devices/0000\:01\:00.1/driver_override
        echo 0000:01:00.1 > /sys/bus/pci/drivers_probe
    */
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

    if (type == "genpack") {
        return run(system_file, data_file, swap_file, {
                .name = vmname,
                .virtiofs_path = virtiofs_path,
                .memory = memory,
                .cpus = cpus,
                .net = net,
                .usb = usb,
                .disks = disks,
                .pci = pci,
                .cdrom = cdrom,
                .append = append? std::make_optional(append) : std::nullopt,
                .display = display? std::make_optional(display) : std::nullopt,
                .stdio_console = false,
                .firmware_files = firmware_files,
                .qemu_env = qemu_env
            } );
    } else if (type == "bios") {
        return run_bios({
                .name = vmname,
                .virtiofs_path = virtiofs_path,
                .memory = memory,
                .cpus = cpus,
                .net = net,
                .usb = usb,
                .disks = disks,
                .pci = pci,
                .cdrom = cdrom,
                .display = display? std::make_optional(display) : std::nullopt,
                .stdio_console = false,
                .firmware_files = firmware_files,
                .qemu_env = qemu_env
            } );
    } else {
        throw std::runtime_error("Unknown VM type '" + type + "'.");
    }
}

static int console(const std::string& vmname)
{
    auto sock = sock_connect(console_sock(vmname));
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
    std::ifstream(qemu_pid(vmname)) >> pid;
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
    std::vector<std::future<std::optional<std::tuple<std::string,uint64_t,uint16_t,uint64_t,uint64_t>>>> threads;
    if (std::filesystem::exists(run_dir()) && std::filesystem::is_directory(run_dir())) {
        for (const auto& entry : std::filesystem::directory_iterator(run_dir())) {
            if (!entry.is_directory()) continue;
            threads.push_back(std::async(check_running_vm, entry.path().filename()));
        }
    }

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
        obj["qmp"] = qmp_sock(vmname);
        obj["monitor"] = monitor_sock(vmname);
        if (std::filesystem::exists(console_sock(vmname))) {
            obj["console"] = console_sock(vmname);
        }
        obj["qemu-pid"] = qemu_pid(vmname);
        obj["qga"] = qga_sock(vmname);
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
    run_command.add_argument("-b", "--bridge").nargs(1);
    run_command.add_argument("--virtiofs-path").nargs(1);
    run_command.add_argument("--no-kvm").default_value(false).implicit_value(true);
    run_command.add_argument("--append").nargs(1);
    run_command.add_argument("--display").nargs(1);
    run_command.add_argument("--hvc").default_value(false).implicit_value(true);
    run_command.add_argument("--pci").nargs(1);
    run_command.add_argument("--no-shutdown").default_value(false).implicit_value(true);
    run_command.add_argument("system_file").nargs(1).help("System file (or C drive image in BIOS mode)");
    program.add_subparser(run_command);

    argparse::ArgumentParser service_command("service");
    service_command.add_description("Run VM as systemd service");
    service_command.add_argument("-b", "--bridge").nargs(1).help("Bridge interface when network is not explicitly specified");
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
        auto virtiofs_path = run_command.present("--virtiofs-path");
#ifndef __VSCODE_ACTIVE_FILE__
        if (virtiofs_path.has_value() && !is_root_user()) throw std::runtime_error("You must be root user to use virtiofs.");
#endif
        if (!std::filesystem::exists(system_file)) throw std::runtime_error(system_file + " does not exist.");

        std::vector<std::tuple<std::string,std::optional<std::string>,bool>> net;
        auto bridge = run_command.present("-b");
        if (bridge.has_value()) {
            net.push_back({bridge.value(), std::nullopt/*generate mac address automatically*/, true});
        }

        auto real_data_file = (volatile_data || data_file.has_value())? 
                    std::make_optional(volatile_data? create_temporary_data_file() : std::filesystem::path(data_file.value()))
                    : std::nullopt;
        
        auto pci = run_command.get<std::vector<std::string>>("--pci");

        if (run_command.get<bool>("--bios")) {
            auto virtio = !run_command.get<bool>("--no-virtio-for-bios-disks");
            std::vector<std::pair<std::filesystem::path,bool>> disks = {{system_file, virtio}};
            if (real_data_file.has_value()) disks.push_back({real_data_file.value(), virtio});
            return run_bios({
                    .name = run_command.present("-n"),
                    .virtiofs_path = run_command.present("--virtiofs-path"),
                    .memory = run_command.get<uint32_t>("-m"),
                    .cpus = run_command.get<uint16_t>("-c"),
                    .kvm = run_command.get<bool>("--no-kvm")? std::make_optional(false) : std::nullopt,
                    .net = net,
                    .disks = disks,
                    .pci = pci,
                    .cdrom = run_command.present("--cdrom"),
                    .display = run_command.present("--display"),
                    .hvc = run_command.get<bool>("--hvc"),
                    .stdio_console = true,
                    .no_shutdown = run_command.get<bool>("--no-shutdown")
                } );
        }
        // else 
        return run(system_file, real_data_file, std::nullopt, {
                .name = run_command.present("-n"),
                .virtiofs_path = run_command.present("--virtiofs-path"),
                .memory = run_command.get<uint32_t>("-m"),
                .cpus = run_command.get<uint16_t>("-c"),
                .kvm = run_command.get<bool>("--no-kvm")? std::make_optional(false) : std::nullopt,
                .net = net,
                .pci = pci,
                .cdrom = run_command.present("--cdrom"),
                .append = run_command.present("--append"),
                .display = run_command.present("--display"),
                .hvc = run_command.get<bool>("--hvc"),
                .stdio_console = true,
                .no_shutdown = run_command.get<bool>("--no-shutdown")
            } );
    }

    if (program.is_subcommand_used("service")) {
        const std::filesystem::path& vm_dir = service_command.get("vm-dir");
        const std::optional<std::string>& vmname = service_command.present("--name");
        return service(
            vmname.value_or(std::filesystem::canonical(vm_dir).filename().string()),
            vm_dir, service_command.present("-b"));
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
