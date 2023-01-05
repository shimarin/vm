#include <iostream>
#include <filesystem>
#include <optional>
#include <vector>
#include <cassert>
#include <future>

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <termios.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <sys/file.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <openssl/md5.h>
#include <libsmartcols/libsmartcols.h>
#include <systemd/sd-daemon.h>
#include <argparse/argparse.hpp>
#include <iniparser4/iniparser.h>

#include "json_messaging.h"

template <typename T>
class Finally {
    std::function<void(const T&)> func;
    const T& arg;
public:
    Finally(std::function<void(const T&)> _func, const T& _arg) : func(_func), arg(_arg) {}
    ~Finally() { func(arg); }
};

std::filesystem::path run_dir = "/run/vm";

bool is_root_user()
{
    return (getuid() == 0);
}

std::filesystem::path get_proc_fd_path(int fd)
{
    static auto proc_fd = std::filesystem::path("/proc") / std::to_string(getpid()) / "fd";
    return proc_fd / std::to_string(fd);
}

std::pair<std::filesystem::path,std::optional<std::filesystem::path>> 
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

std::optional<std::string> get_default_hostname(const std::filesystem::path& system_file)
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

std::filesystem::path create_temporary_data_file(bool format = true)
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

std::string generate_temporary_hostname()
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

auto vm_run_dir(const std::string& vmname) {return run_dir / vmname;}
auto qmp_sock(const std::string& vmname) {return vm_run_dir(vmname) / "qmp.sock";}
auto monitor_sock(const std::string& vmname) {return vm_run_dir(vmname) / "monitor.sock";}
auto console_sock(const std::string& vmname) {return vm_run_dir(vmname) / "console.sock";}
auto qga_sock(const std::string& vmname) {return vm_run_dir(vmname) / "qga.sock";}
auto virtiofs_sock(const std::string& vmname) {return vm_run_dir(vmname) / "virtiofs.sock";}

int sock_connect(const std::filesystem::path& sock_path)
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

auto qmp_connect(const std::string& vmname) {return sock_connect(qmp_sock(vmname));}

bool qmp_ping(const std::string& vmname)
{
    auto qmp_fd = qmp_connect(vmname);
    if (qmp_fd < 0) return false;
    //else
    receive_message(qmp_fd);
    shutdown(qmp_fd, SHUT_WR);
    close(qmp_fd);
    return true;
}

bool qmp_shutdown(const std::string& vmname, bool force)
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

bool is_o_direct_supported(const std::filesystem::path& file)
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
    const uint32_t memory = 1024;
    const uint16_t cpus = 1;
    const std::optional<bool> kvm = std::nullopt;
    const std::vector<std::tuple<std::string/*bridge*/,std::optional<std::string>/*mac address*/,bool/*vhost*/>>& net = {};
    const std::vector<std::filesystem::path>& usb = {};
    const std::vector<std::pair<std::filesystem::path,bool/*virtio*/>>& disks = {};
    const std::optional<std::filesystem::path>& cdrom = std::nullopt;
    const std::optional<std::string>& append = std::nullopt;
    const std::optional<std::string>& display = std::nullopt;
    const bool hvc = false;
    const bool stdio_console = false;
};

int lock_vm(const std::string& vmname)
{
    auto vm_run_dir_fd = open(vm_run_dir(vmname).c_str(), O_RDONLY, 0);
    if (vm_run_dir_fd < 0) throw std::runtime_error(std::string("open(") + vm_run_dir(vmname).string() + ") failed");

    if (flock(vm_run_dir_fd, LOCK_EX|LOCK_NB) < 0) {
        close(vm_run_dir_fd);
        if (errno == EWOULDBLOCK) return -1;
        else throw std::runtime_error(std::string("flock(") + run_dir.string() + ") failed");
    }
    return vm_run_dir_fd;
}

pid_t run_virtiofsd(const std::string& vmname, const std::filesystem::path& path)
{
    auto pid = fork();
    if (pid < 0) throw std::runtime_error("fork() failed");
    if (pid == 0) {
        _exit(execlp("/usr/libexec/virtiofsd", "/usr/libexec/virtiofsd", 
            "-f", "-o", ("cache=none,flock,posix_lock,xattr,allow_direct_io,source=" + path.string()).c_str(),
            ("--socket-path=" + virtiofs_sock(vmname).string()).c_str(),
            NULL));
    }
    //else
    return pid;
}

void apply_options_to_qemu_cmdline(const std::string& vmname, std::vector<std::string>& qemu_cmdline, const RunOptions& options)
{
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
    if (options.cpus > 1) {
        qemu_cmdline.insert(qemu_cmdline.end(), {"-smp", "cpus=" + std::to_string(options.cpus)});
    }
    if (options.kvm.value_or(access("/dev/kvm", R_OK|W_OK) == 0)) {
        qemu_cmdline.insert(qemu_cmdline.end(), {"-cpu", "host", "-enable-kvm"});
    }
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

    if (options.usb.size() > 0) {
        qemu_cmdline.push_back("-usb");
        for (const auto& dev:options.usb) {
            qemu_cmdline.insert(qemu_cmdline.end(), {
                "-device", "usb-host,hostdevice=" + dev.string()
            });
        }
    }

    if (options.cdrom.has_value()) {
        qemu_cmdline.insert(qemu_cmdline.end(), {
            "-cdrom", options.cdrom.value().string()
        });
    }
}

void append_disk_to_qemu_cmdline(std::vector<std::string>& qemu_cmdline, const std::filesystem::path& disk, bool virtio = true)
{
    qemu_cmdline.insert(qemu_cmdline.end(), {"-drive", "file=" + disk.string() + ",format=raw,media=disk"
        + (virtio? ",if=virtio" : "")
        + (is_o_direct_supported(disk)? ",aio=native,cache.direct=on":"") });
}

void apply_virtiofs_to_qemu_cmdline(const std::string& vmname, std::vector<std::string>& qemu_cmdline, pid_t virtiofsd_pid)
{
    qemu_cmdline.insert(qemu_cmdline.end(), {
        "-chardev", "socket,id=virtiofs,path=" + virtiofs_sock(vmname).string(),
        "-device", "vhost-user-fs-pci,queue-size=1024,chardev=virtiofs,tag=fs"
    });
}

int run_qemu(const std::string& vmname, const std::vector<std::string>& cmdline, pid_t virtiofsd_pid = -1)
{
    auto qemu_pid = fork();
    if (qemu_pid < 0) throw std::runtime_error("fork() failed");
    if (qemu_pid == 0) { // child process
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

int run(const std::filesystem::path& system_file, const std::optional<std::filesystem::path>& data_file, 
    const RunOptions& options)
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
    std::vector<std::string> qemu_cmdline = {
        "qemu-system-x86_64", "-M","q35",
        "-m", std::to_string(options.memory),
        "-object", "memory-backend-memfd,id=mem,size=" + std::to_string(options.memory) + "M,share=on", "-numa", "node,memdev=mem",
        "-kernel", kernel.string(), "-append", append,
        "-display", options.display.value_or("none"),
        "-monitor", "unix:" + monitor_sock(vmname).string() + ",server,nowait",
        "-qmp", "unix:" + qmp_sock(vmname).string() + ",server,nowait",
        "-chardev", "socket,path=" + qga_sock(vmname).string() + ",server=on,wait=off,id=qga0",
        "-device", "virtio-serial", "-device", "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0",
        "-drive", "file=" + system_file.string() + ",format=raw,index=0,readonly=on,media=disk,if=virtio,aio=native,cache.direct=on"
    };

    apply_options_to_qemu_cmdline(vmname, qemu_cmdline, options);

    if (initramfs.has_value()) {
        qemu_cmdline.insert(qemu_cmdline.end(), {"-initrd", initramfs.value()});
    }
    if (data_file.has_value()) {
        auto _ = data_file.value();
        qemu_cmdline.insert(qemu_cmdline.end(), {"-drive", "file=" + _.string() + ",format=raw,index=1,media=disk,if=virtio" 
            + (is_o_direct_supported(_)? ",aio=native,cache.direct=on":"") });
    }

    for (const auto& [disk,virtio] : options.disks) {
        append_disk_to_qemu_cmdline(qemu_cmdline, disk, virtio);
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


    std::cout << "Executing QEMU..." << std::endl;
    return run_qemu(vmname, qemu_cmdline, virtiofsd_pid);
}

int run_bios(const RunOptions& options)
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
        "qemu-system-x86_64", "-M","q35",
        "-m", std::to_string(options.memory),
        "-object", "memory-backend-memfd,id=mem,size=" + std::to_string(options.memory) + "M,share=on", "-numa", "node,memdev=mem",
        "-display", options.display.value_or("none"),
        "-monitor", "unix:" + monitor_sock(vmname).string() + ",server,nowait",
        "-qmp", "unix:" + qmp_sock(vmname).string() + ",server,nowait",
        "-chardev", "socket,path=" + qga_sock(vmname).string() + ",server=on,wait=off,id=qga0",
        "-device", "virtio-serial", "-device", "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0"
    };

    apply_options_to_qemu_cmdline(vmname, qemu_cmdline, options);
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

    for (const auto& [disk,virtio] : options.disks) {
        append_disk_to_qemu_cmdline(qemu_cmdline, disk, virtio);
    }

    std::cout << "Executing QEMU(BIOS)..." << std::endl;
    return run_qemu(vmname, qemu_cmdline, virtiofsd_pid);
}

int service(const std::string& vmname, const std::filesystem::path& vm_root, std::optional<const std::string> bridge)
{
    std::cout << "VM root = " << vm_root << std::endl;
    std::cout << "service bridge=" << bridge.value_or("(not specified)") << " vmname=" << vmname << std::endl;

    auto vm_dir = vm_root / vmname;
    std::cout << "VM dir = " << vm_dir << std::endl;
    if (!std::filesystem::exists(vm_dir)) throw std::runtime_error(vm_dir.string() + " does not exist.");
    if (!std::filesystem::is_directory(vm_dir)) throw std::runtime_error(vm_dir.string() + " is not a directory.");

    auto system_file = vm_dir / "system";
    auto data_file = std::make_optional(vm_dir / "data");
    if (!std::filesystem::exists(data_file.value())) data_file = std::nullopt;
    auto virtiofs_path = is_root_user()? std::make_optional(vm_dir / "fs") : std::nullopt;
    if (virtiofs_path.has_value()) std::filesystem::create_directories(virtiofs_path.value());

    auto ini_path = vm_dir / "vm.ini";
    auto ini = std::shared_ptr<dictionary>(std::filesystem::exists(ini_path)? iniparser_load(ini_path.c_str()) : dictionary_new(0), iniparser_freedict);

    uint32_t memory = iniparser_getint(ini.get(), ":memory", 1024);
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
        auto virtio = iniparser_getboolean(ini.get(), "virtio", true);
        if (std::filesystem::exists(disk)) disks.push_back({disk,virtio});
    }

    auto cdrom = 
        std::filesystem::exists(vm_dir / "cdrom")? std::make_optional(vm_dir / "cdrom") : std::nullopt;

    if (type == "genpack") {
        return run(system_file, data_file, {
                .name = vmname,
                .virtiofs_path = virtiofs_path,
                .memory = memory,
                .cpus = cpus,
                .net = net,
                .usb = usb,
                .disks = disks,
                .cdrom = cdrom,
                .append = append? std::make_optional(append) : std::nullopt,
                .display = display? std::make_optional(display) : std::nullopt,
                .stdio_console = false
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
                .cdrom = cdrom,
                .display = display? std::make_optional(display) : std::nullopt,
                .stdio_console = false
            } );
    } else {
        throw std::runtime_error("Unknown VM type '" + type + "'.");
    }
}

int console(const std::string& vmname)
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

std::optional<std::tuple<std::string/*vmname*/,uint64_t/*memory*/,uint16_t/*cpus*/>> check_running_vm(const std::string& vmname)
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

    return std::make_tuple(vmname, memory, ncpus);
}

std::vector<std::tuple<std::string,uint64_t,uint16_t>> collect_running_vm_info()
{
    std::vector<std::future<std::optional<std::tuple<std::string,uint64_t,uint16_t>>>> threads;
    if (std::filesystem::exists(run_dir) && std::filesystem::is_directory(run_dir)) {
        for (const auto& entry : std::filesystem::directory_iterator(run_dir)) {
            if (!entry.is_directory()) continue;
            threads.push_back(std::async(check_running_vm, entry.path().filename()));
        }
    }

    std::vector<std::tuple<std::string,uint64_t,uint16_t>> vms;
    for (auto& thread : threads) {
        auto vm = thread.get();
        if (vm.has_value()) vms.push_back(vm.value());
    }

    std::sort(vms.begin(), vms.end(), [](auto a, auto b) {
        return std::get<0>(a) < std::get<0>(b);
    });

    return vms;
}

int show(std::optional<std::string> vmname)
{
    auto result = nlohmann::json::array();

    auto set_properties = [](nlohmann::json& obj, const std::string& vmname, uint64_t memory, uint16_t cpus) {
        obj["name"] = vmname;
        obj["memory"] = memory;
        obj["cpus"] = cpus;
        obj["qmp"] = qmp_sock(vmname);
        obj["monitor"] = monitor_sock(vmname);
        if (std::filesystem::exists(console_sock(vmname))) {
            obj["console"] = console_sock(vmname);
        }
        obj["qga"] = qga_sock(vmname);
    };

    if (vmname.has_value()) {
        auto vm = check_running_vm(vmname.value());
        if (vm.has_value()) {
            nlohmann::json entry;
            const auto& [vmname,memory,cpus] = vm.value();
            set_properties(entry, vmname, memory,cpus);
            result.push_back(entry);
        }
    } else {
        for (const auto& [vmname, memory, cpus]:collect_running_vm_info()) {
            nlohmann::json entry;
            set_properties(entry, vmname, memory, cpus);
            result.push_back(entry);
        }
    }

    std::cout << result << std::endl;
    return 0;
}

int list()
{
    std::shared_ptr<libscols_table> table(scols_new_table(), scols_unref_table);
    if (!table) throw std::runtime_error("scols_new_table() failed");
    scols_table_new_column(table.get(), "NAME", 0.1, 0);
    scols_table_new_column(table.get(), "MEMORY(MB)", 0.1, SCOLS_FL_RIGHT);
    scols_table_new_column(table.get(), "CPU", 0.1, SCOLS_FL_RIGHT);
    auto sep = scols_table_new_line(table.get(), NULL);
    scols_line_set_data(sep, 0, "-------");
    scols_line_set_data(sep, 1, "----------");
    scols_line_set_data(sep, 2, "---");
    for (const auto& [vmname, memory, cpus]:collect_running_vm_info()) {
        auto line = scols_table_new_line(table.get(), NULL);
        if (!line) throw std::runtime_error("scols_table_new_line() failed");
        scols_line_set_data(line, 0, vmname.c_str());
        scols_line_set_data(line, 1, std::to_string(memory / 1024 / 1024).c_str());
        scols_line_set_data(line, 2, std::to_string(cpus).c_str());
    }
    scols_print_table(table.get());
    return 0;
}

static int _main(int argc, char* argv[])
{
    std::filesystem::path default_vm_root = "/var/vm";
    if (!is_root_user()) {
        const auto xdg_runtime_dir = getenv("XDG_RUNTIME_DIR");
        if (xdg_runtime_dir) run_dir = std::filesystem::path(xdg_runtime_dir) / "vm";
        const auto home = getenv("HOME");
        if (home) default_vm_root = std::filesystem::path(home) / "vm";
    }

    argparse::ArgumentParser program(argv[0]);

    argparse::ArgumentParser run_command("run");
    run_command.add_description("Run VM specifying system file");
    run_command.add_argument("-n", "--name").nargs(1);
    run_command.add_argument("-m", "--memory").default_value<uint32_t>(1024).scan<'u',uint32_t>();
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
    run_command.add_argument("system_file").nargs(1).help("System file (or C drive image in BIOS mode)");
    program.add_subparser(run_command);

    argparse::ArgumentParser service_command("service");
    service_command.add_description("Run VM as systemd service");
    service_command.add_argument("-r", "--vm-root").nargs(1).default_value(default_vm_root.string());
    service_command.add_argument("-b", "--bridge").nargs(1).help("Bridge interface when network is not explicitly specified");
    service_command.add_argument("vmname").nargs(1);
    program.add_subparser(service_command);

    argparse::ArgumentParser console_command("console");
    console_command.add_description("Connect to VM console");
    console_command.add_argument("vmname").nargs(1);
    program.add_subparser(console_command);

    argparse::ArgumentParser start_command("start");
    start_command.add_description("Start VM using systemd");
    start_command.add_argument("-c", "--console").default_value(false).implicit_value(true);
    start_command.add_argument("vmname").nargs(1);
    program.add_subparser(start_command);

    argparse::ArgumentParser stop_command("stop");
    stop_command.add_description("Stop VM");
    stop_command.add_argument("-c", "--console").default_value(false).implicit_value(true);
    stop_command.add_argument("-f", "--force").default_value(false).implicit_value(true);
    stop_command.add_argument("vmname").nargs(1);
    program.add_subparser(stop_command);

    argparse::ArgumentParser show_command("show");
    show_command.add_argument("vmname").nargs(argparse::nargs_pattern::optional);
    program.add_subparser(show_command);

    argparse::ArgumentParser list_command("list");
    program.add_subparser(list_command);

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
        } else if (program.is_subcommand_used("start")) {
            std::cerr << start_command;
        } else if (program.is_subcommand_used("stop")) {
            std::cerr << stop_command;
        } else if (program.is_subcommand_used("show")) {
            std::cerr << show_command;
        } else if (program.is_subcommand_used("list")) {
            std::cerr << list_command;
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
                    .cdrom = run_command.present("--cdrom"),
                    .display = run_command.present("--display"),
                    .hvc = run_command.get<bool>("--hvc"),
                    .stdio_console = true
                } );
        }
        // else 
        return run(system_file, real_data_file, {
                .name = run_command.present("-n"),
                .virtiofs_path = run_command.present("--virtiofs-path"),
                .memory = run_command.get<uint32_t>("-m"),
                .cpus = run_command.get<uint16_t>("-c"),
                .kvm = run_command.get<bool>("--no-kvm")? std::make_optional(false) : std::nullopt,
                .net = net,
                .cdrom = run_command.present("--cdrom"),
                .append = run_command.present("--append"),
                .display = run_command.present("--display"),
                .hvc = run_command.get<bool>("--hvc"),
                .stdio_console = true
            } );
    }

    if (program.is_subcommand_used("service")) {
        return service(service_command.get("vmname"), service_command.get("-r"), service_command.present("-b"));
    }

    if (program.is_subcommand_used("console")) {
        return console(console_command.get("vmname"));
    }

    if (program.is_subcommand_used("start")) {
        auto vmname = start_command.get("vmname");
        if (qmp_ping(vmname)) throw std::runtime_error(vmname + " is already running");
        auto pid = fork();
        if (pid < 0) throw std::runtime_error("fork() failed");
        if (pid == 0) {
            auto service_name = ("vm@" + vmname).c_str();
            if (is_root_user()) {
                _exit(execlp("systemctl", "systemctl", "start", service_name, NULL));
            } else {
                _exit(execlp("systemctl", "systemctl", "--user", "start", service_name, NULL));
            }
        }
        int wstatus;
        waitpid(pid, &wstatus, 0);
        if (!WIFEXITED(wstatus)) throw std::runtime_error("systemctl command terminated abnormally");
        auto status = WEXITSTATUS(wstatus);
        if (status == 0 && start_command.get<bool>("-c")) {
            return console(vmname);
        }
        //else
        return status;
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

    if (program.is_subcommand_used("show")) {
        auto vmname = show_command.present("vmname");
        return show(vmname);
    }

    if (program.is_subcommand_used("list")) {
        return list();
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
