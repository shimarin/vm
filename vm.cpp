#include <iostream>
#include <fstream>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <variant>

#include <memory.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/file.h>

#include <iniparser4/iniparser.h>

static const char* HOME = getenv("HOME");
static const char* XDG_RUNTIME_DIR = getenv("XDG_RUNTIME_DIR");
static const std::filesystem::path home(HOME? HOME : "."), run(XDG_RUNTIME_DIR? XDG_RUNTIME_DIR : ".");
static const std::filesystem::path vm_root = home / ("vm"), run_root = run / ("vm");

static const std::filesystem::path default_ini_path = vm_root / "default.ini";
static auto default_ini = std::shared_ptr<dictionary>(std::filesystem::exists(default_ini_path)? iniparser_load(default_ini_path.c_str()) : dictionary_new(0), iniparser_freedict);
static const char* default_bridge = iniparser_getstring(default_ini.get(), ":bridge", std::filesystem::exists("/sys/class/net/br0/bridge")? "br0" : NULL);

class Finally {
    std::function<void()> func;
public:
    Finally(std::function<void()> _func) : func(_func) {}
    ~Finally() { func(); }
};

std::vector<std::string> getopt(
    int argc, char* argv[], 
    const std::vector<std::tuple<
        std::optional<char>/*shortopt*/,
        std::optional<std::string>/*longopt*/,
        std::variant<
            std::function<void(void)>, // 0: no arg
            std::function<void(const std::optional<std::string>&)>, // 1: optional string arg
            std::function<void(const std::string&)> // 2: required string arg
        >/*func*/
    >>& opts)
{
    std::string shortopts;
    std::vector<struct option> longopts;
    std::map<std::string,std::variant<
        std::function<void(void)>,
        std::function<void(const std::optional<std::string>&)>,
        std::function<void(const std::string&)>
    >> funcs;
    for (const auto& opt:opts) {
        if (std::get<0>(opt).has_value()) {
            char shortopt = std::get<0>(opt).value();
            const auto& func = std::get<2>(opt);
            shortopts += shortopt;
            if (std::holds_alternative<std::function<void(const std::optional<std::string>&)>>(func)) shortopts += "::";
            else if (std::holds_alternative<std::function<void(const std::string&)>>(func)) shortopts += ":";
            funcs[std::string(1, shortopt)] = func;
        }
        if (std::get<1>(opt).has_value()) {
            const auto& longopt = std::get<1>(opt).value();
            const auto& shortopt = std::get<0>(opt);
            const auto& func = std::get<2>(opt);
            auto arg_required = std::holds_alternative<std::function<void(const std::optional<std::string>&)>>(func)? optional_argument
                : ((std::holds_alternative<std::function<void(const std::string&)>>(func))? required_argument : no_argument);
            longopts.push_back((struct option) {
                longopt.c_str(),
                arg_required,
                0,
                shortopt.has_value()? shortopt.value() : 0
            });
            funcs[longopt] = func;
        }
    }

    struct option* clongopts = new struct option[longopts.size() + 1];
    struct option* p = clongopts;
    for (const auto& lo:longopts) { 
        memcpy(p, &lo, sizeof(*p));
        p++;
    }
    memset(p, 0, sizeof(*p));
    int c;
    int longindex = 0;
    while ((c = getopt_long(argc, argv, shortopts.c_str(), clongopts, &longindex)) >= 0) {
        const auto func = funcs.find(c == 0? clongopts[longindex].name : std::string(1,(char)c));
        if (func != funcs.end()) {
            if (std::holds_alternative<std::function<void(const std::optional<std::string>&)>>(func->second)) {
                std::get<1>(func->second)(optarg? std::optional<std::string>(optarg) : std::nullopt);
            } else if (std::holds_alternative<std::function<void(const std::string&)>>(func->second)) {
                std::get<2>(func->second)(optarg? optarg : "");
            } else {
                std::get<0>(func->second)();
            }
        }
    }
    delete []clongopts;

    std::vector<std::string> non_option_args;
    for (int i = optind; i < argc; i++) {
        non_option_args.push_back(argv[i]);
    }

    return non_option_args;
}

void create_bootimage(const std::filesystem::path& bootimage_path, const std::string& hostname)
{
    auto bootimage_dir = bootimage_path.parent_path();
    std::filesystem::create_directories(bootimage_dir);

    std::filesystem::copy("/usr/lib/grub/i386-pc/boot.img", bootimage_path, std::filesystem::copy_options::overwrite_existing);

    std::filesystem::path memdisk_tar = bootimage_dir / "memdisk.tar";
    Finally memdisk_tar_fin([&memdisk_tar]{if (std::filesystem::exists(memdisk_tar)) std::filesystem::remove(memdisk_tar);});

    {
        std::ofstream f(memdisk_tar, std::ios::binary|std::ios::trunc);
        if (!f) throw std::runtime_error("memdisk.tar cannot be created");

        std::ostringstream grub_cfg;
        grub_cfg << "serial --speed=115200" << std::endl;
        grub_cfg << "terminal_input serial console" << std::endl;
        grub_cfg << "terminal_output serial console" << std::endl;
        grub_cfg << "set hostname=\"" << hostname << '"' << std::endl;
        grub_cfg << "set hostuid=\"" << getuid() << '"' << std::endl;
        grub_cfg << "set hostgid=\"" << getgid() << '"' << std::endl;
        grub_cfg << "if [ -f (hd1)/boot/grub/grub.cfg ]; then" << std::endl;
        grub_cfg << "  set root=(hd1)" << std::endl;
        grub_cfg << "  source /boot/grub/grub.cfg" << std::endl;
        grub_cfg << "elif [ -f (hd1)/boot/kernel ]; then" << std::endl;
        grub_cfg << "  linux (hd1)/boot/kernel net.ifnames=0 console=tty0 console=ttyS0,115200n8r systemd.hostname=$hostname systemd.firstboot=0 hostuid=$hostuid hostgid=$hostgid" << std::endl;
        grub_cfg << "  initrd (hd1)/boot/initramfs" << std::endl;
        grub_cfg << "  boot" << std::endl;
        grub_cfg << "fi" << std::endl;

        const auto& content_str = grub_cfg.str();

        struct {
            char name[100];
            char mode[8];
            char uid[8];
            char gid[8];
            char size[12];
            char mtime[12];
            char chksum[8];
            char typeflag;
            char linkname[100];
            char magic[6];
            char version[2];
            char uname[32];
            char gname[32];
            char devmajor[8];
            char devminor[8];
            char prefix[155];
            char padding[12];
        } tar_header;
        memset(&tar_header, 0, sizeof(tar_header));
        strcpy(tar_header.name, "boot/grub/grub.cfg");
        strcpy(tar_header.mode, "0000644");
        strcpy(tar_header.uid, "0000000");
        strcpy(tar_header.gid, "0000000");
        sprintf(tar_header.size, "%07lo", content_str.length());
        sprintf(tar_header.mtime, "%011lo", time(NULL));
        tar_header.typeflag = '\0'; // regular file
        strcpy(tar_header.magic, "ustar");

        int sum = 0;
        for (int i = 0; i < sizeof(tar_header); i++) {
            sum += ((const uint8_t*)&tar_header)[i];
        }
        sprintf(tar_header.chksum, "%07o", sum);

        f.write((const char*)&tar_header, sizeof(tar_header));
        f << content_str;
        const size_t block_size = 512;
        char pad[block_size];
        memset(pad, 0, sizeof(pad));
        auto mod = content_str.length() % block_size;
        if (mod > 0) f.write(pad, block_size - mod);
        f.write(pad, block_size);
        f.write(pad, block_size);
    }

    int fd = open(bootimage_path.c_str(), O_APPEND|O_WRONLY);
    if (fd < 0) throw std::runtime_error("open(bootimage_path, O_APPEND) failed");
    Finally fd_fin([fd]{close(fd);});

    auto pid = fork();
    if (pid < 0) throw std::runtime_error("fork() failed");
    if (pid == 0) {
        // subprocess
        dup2(fd, STDOUT_FILENO);
        close(fd);
        _exit(execlp("grub-mkimage", "grub-mkimage", "-O", "i386-pc", "-p", "/boot/grub", 
            "-m", memdisk_tar.c_str(),
            "memdisk", "biosdisk", "normal", "linux", "echo", "squash4", "serial", "terminal", 
            "configfile", "loopback", "test", "tar", "xfs", "btrfs", "minicmd", "probe", "regexp", "xzio",
            NULL));
    }
    // else(main process)
    int wstatus;
    waitpid(pid, &wstatus, 0);
    try {
        if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) {
            throw std::runtime_error("grub-mkimage failed");
        }
        if (lseek(fd, 0, SEEK_END) < 512 * 1024) {
            if (ftruncate(fd, 512 * 1024) < 0) {
                throw std::runtime_error("ftruncate() failed");
            }
        }
    }
    catch (...) {
        std::filesystem::remove(bootimage_path);
        throw;
    }
}

bool validate_mac_address(const std::string& mac_str)
{
    if (mac_str.length() != 17) return false;
    //else
    for (int i = 0; i < 17; i++) {
      char c = tolower(mac_str[i]);
      if (i % 3 == 2) {
        if ( c != ':') return false; // invalid tokenizer
        else continue;
      }
      //else
      if (!isdigit(c) && (c < 'a' || c > 'f')) return false; // invalid hex char
    }

    return true;
}

std::string get_or_generate_mac_address(const std::string& vmname, int num)
{
    auto cache_dir = vm_root / vmname / "cache";

    auto cache_file_path = cache_dir / (std::string("eth") + std::to_string(num));
    {
        // load from cache
        std::ifstream cache_file(cache_file_path);
        if (cache_file) {
            std::string mac_str;
            cache_file >> mac_str;
            if (validate_mac_address(mac_str)) return mac_str;
        }
    }
    //else
    char buf[3];
    auto fd = open("/dev/urandom", O_RDONLY, 0);
    if (fd < 0) throw std::runtime_error("open(/dev/urandom) failed");
    if (read(fd, buf, 3) < 3) throw std::runtime_error("read(/dev/urandom, 3) failed");
    close(fd);

    uint8_t mac[6];
    mac[0] = 0x52;
    mac[1] = 0x54;
    mac[2] = 0x00;
    mac[3] = buf[0] & 0x7f;
    mac[4] = buf[1];
    mac[5] = buf[2];

    char mac_str[18];
    sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", (int)mac[0], (int)mac[1], (int)mac[2], (int)mac[3], (int)mac[4], (int)mac[5]);

    std::filesystem::create_directories(cache_file_path.parent_path());
    std::ofstream cache_file(cache_file_path);
    if (cache_file) {
        cache_file << mac_str;
    }
    return mac_str;
}

static void create_data_image(const std::filesystem::path& data_image_path)
{
    auto fd = creat(data_image_path.c_str(), S_IRUSR|S_IWUSR);
    if (fd < 0) throw std::runtime_error("creat() failed");
    if (ftruncate(fd, 1024 * 1024 * 1024/*1GiB*/) < 0) {
        close(fd);
        throw std::runtime_error("Createing data image failed");
    }
    close(fd);
    //else
    auto pid = fork();
    if (pid < 0) throw std::runtime_error("fork() failed");
    if (pid == 0) {
        _exit(execlp("mkfs.btrfs", "mkfs.btrfs", "-f", data_image_path.c_str(), NULL));
    }
    // else(main process)
    int wstatus;
    waitpid(pid, &wstatus, 0);
    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) throw std::runtime_error("mkfs.btrfs failed");
}

int vm(const std::string& name)
{
    auto vm_dir = vm_root / name, run_dir = run_root / name;

    if (!std::filesystem::is_directory(vm_dir)) throw std::runtime_error("No VM found");

    auto system_image = vm_dir / "system", data_image = vm_dir / "data", swapfile = vm_dir / "swapfile", cdrom = vm_dir / "cdrom";
    if (!std::filesystem::exists(system_image)) throw std::runtime_error("No system image found");

    if (!std::filesystem::exists(data_image)) {
        std::cout << "Data image not found. creating..." << std::endl;
        create_data_image(data_image);
    }

    // parse ini
    auto ini_path = vm_dir / "vm.ini";
    auto ini = std::shared_ptr<dictionary>(std::filesystem::exists(ini_path)? iniparser_load(ini_path.c_str()) : dictionary_new(0), iniparser_freedict);

    auto memory = iniparser_getint(ini.get(), ":memory", iniparser_getint(default_ini.get(), ":memory", 1024));
    if (memory < 256) throw std::runtime_error("Memory too less");
    auto cpus = iniparser_getint(ini.get(), ":cpu", iniparser_getint(default_ini.get(), ":cpu", 1));
    if (cpus < 1) throw std::runtime_error("Invalid cpu number");

    // load virtiofs config
    std::vector<std::pair<std::string,std::filesystem::path>> virtiofses;
    for (int i = 0; i < 10; i++) {
        char buf[16];
        sprintf(buf, "fs%d", i);
        if (iniparser_find_entry(ini.get(), buf) == 0) continue;
        //else
        sprintf(buf, "fs%d:tag", i);
        auto tag = iniparser_getstring(ini.get(), buf, NULL);
        if (!tag) {
            std::cerr << "Tag is not specified for fs " << i << ". fs ignored." << std::endl;
            continue;
        }
        //else
        sprintf(buf, "fs%d:path", i);
        auto path = iniparser_getstring(ini.get(), buf, NULL);
        if (!path) {
            std::cerr << "Path is not specified for fs " << i << ". fs ignored." << std::endl;
            continue;
        }
        virtiofses.push_back({tag, path});
    }

    // load USB config
    std::vector<std::pair<int/*bus*/,int/*addr*/>> usbdevs;
    for (int i = 0; i < 10; i++) {
        char buf[16];
        sprintf(buf, "usb%d", i);
        if (iniparser_find_entry(ini.get(), buf) == 0) continue;
        //else
        sprintf(buf, "usb%d:bus", i);
        auto bus = iniparser_getint(ini.get(), buf, -1);
        if (!bus < 0) {
            std::cerr << "Bus # is not specified for USB " << i << ". USB device ignored." << std::endl;
            continue;
        }
        //else
        sprintf(buf, "usb%d:addr", i);
        auto addr = iniparser_getint(ini.get(), buf, -1);
        if (!addr < 0) {
            std::cerr << "Addr # is not specified for USB " << i << ". USB device ignored." << std::endl;
            continue;
        }
        usbdevs.push_back({bus, addr});
    }

    // rng
    bool hwrng = iniparser_getboolean(ini.get(), ":hwrng", iniparser_getboolean(default_ini.get(), ":hwrng", 0));

    // rtc
    auto rtc = iniparser_getstring(ini.get(), ":rtc", iniparser_getstring(default_ini.get(), ":rtc", NULL));

    // kvm
    bool kvm = (access("/dev/kvm", R_OK|W_OK) == 0)? iniparser_getboolean(ini.get(), ":kvm", iniparser_getboolean(default_ini.get(), ":kvm", 1)) : false;

    std::vector<std::string> qemu_cmdline = {
        "qemu-system-x86_64","-cpu", "host", "-M","q35",
        "-m", std::to_string(memory),
        "-smp", "cpus=" + std::to_string(cpus), 
        "-object", "memory-backend-memfd,id=mem,size=" + std::to_string(memory) + "M,share=on", "-numa", "node,memdev=mem",
        "-nographic", "-serial", "mon:stdio"
    };

    if (kvm) qemu_cmdline.push_back("-enable-kvm");

    if (rtc) {
        qemu_cmdline.push_back("-rtc");
        qemu_cmdline.push_back(rtc);
    }

    std::filesystem::path hwrng_path("/dev/hwrng");
    if (hwrng && std::filesystem::exists(hwrng_path) && std::filesystem::is_character_file(hwrng_path)) {
        qemu_cmdline.push_back("-object");
        qemu_cmdline.push_back(std::string("rng-random,filename=") + hwrng_path.string() + ",id=rng0");
        qemu_cmdline.push_back("-device");
        qemu_cmdline.push_back("virtio-rng-pci,rng=rng0,max-bytes=1024,period=1000");
    } else {
        qemu_cmdline.push_back("-device");
        qemu_cmdline.push_back("virtio-rng-pci");
    }

    int chardev_idx = 0;
    std::vector<std::pair<std::filesystem::path,std::filesystem::path>> virtiofs_sockets;
    for (const auto& fs:virtiofses) {
        auto socket_path = run_dir / ("virtiofs" + std::to_string(chardev_idx) + ".sock");
        auto chardev = std::string("char") + std::to_string(chardev_idx++);
        qemu_cmdline.push_back("-chardev");
        qemu_cmdline.push_back("socket,id=" + chardev + ",path=" + socket_path.string());
        qemu_cmdline.push_back("-device");
        qemu_cmdline.push_back("vhost-user-fs-pci,queue-size=1024,chardev=" + chardev + ",tag=" + fs.first);
        virtiofs_sockets.push_back({fs.second, socket_path});
    }

    auto boot_image = run_dir / "boot.img";
    qemu_cmdline.push_back("-drive");
    qemu_cmdline.push_back(std::string("file=") + boot_image.string() + ",format=raw,index=0,media=disk");

    qemu_cmdline.push_back("-drive");
    qemu_cmdline.push_back(std::string("file=") + system_image.string() + ",format=raw,index=0,readonly=on,media=disk,if=virtio,aio=native,cache.direct=on,readonly=on");
    qemu_cmdline.push_back("-drive");
    qemu_cmdline.push_back(std::string("file=") + data_image.string() + ",format=raw,index=1,media=disk,if=virtio,aio=native,cache.direct=on");

    qemu_cmdline.push_back("-netdev");
    qemu_cmdline.push_back("tap,id=net0,br=br0,helper=/usr/libexec/qemu-bridge-helper");
    qemu_cmdline.push_back("-device");
    qemu_cmdline.push_back("virtio-net-pci,romfile=,netdev=net0,mac=" + get_or_generate_mac_address(name, 0));

    qemu_cmdline.push_back("-usb");
    for (const auto& usbdev:usbdevs) {
        auto bus = usbdev.first;
        auto addr = usbdev.second;
        qemu_cmdline.push_back("-device");
        qemu_cmdline.push_back("usb-host,hostbus=" + std::to_string(bus) + ",hostaddr=" + std::to_string(addr));
    }

    // lock vm
    std::filesystem::create_directories(run_dir);
    auto run_dir_fd = open(run_dir.c_str(), O_RDONLY, 0);
    if (run_dir_fd < 0) throw std::runtime_error(std::string("open(") + run_dir.string() + ") failed");
    Finally run_dir_fd_fin([run_dir_fd]{close(run_dir_fd);});
    if (flock(run_dir_fd, LOCK_EX|LOCK_NB) < 0) {
        if (errno == EWOULDBLOCK) throw std::runtime_error(name + " is already running");
        else throw std::runtime_error(std::string("flock(") + run_dir.string() + ") failed");
    }
    Finally run_dir_fd_lock_fin([run_dir_fd]{flock(run_dir_fd, LOCK_UN);});

    create_bootimage(boot_image, name);

    // run virtiofsds
    // needs patch series: https://patchwork.kernel.org/project/qemu-devel/cover/20200730194736.173994-1-vgoyal@redhat.com/
    std::vector<pid_t> virtiofsd_pids;
    Finally virtiofsd_fin([&virtiofsd_pids]{
        for (auto pid:virtiofsd_pids) {
            std::cout << "Terminating virtiofs at pid=" << pid << std::endl;
            kill(pid, SIGTERM);
        }
        for (auto pid:virtiofsd_pids) {
            waitpid(pid, NULL, 0);
        }
    });
    for (const auto& i:virtiofs_sockets) {
        const auto& source = i.first;
        const auto& socket_path = i.second;
        std::cout << socket_path << std::endl;
        auto pid = fork();
        if (pid < 0) throw std::runtime_error("fork() failed");
        if (pid == 0) {
            _exit(execlp("/usr/libexec/virtiofsd", "/usr/libexec/virtiofsd", 
                "-f", "-o", ("cache=none,flock,posix_lock,xattr,allow_direct_io,source=" + source.string()).c_str(),
                ("--socket-path=" + socket_path.string()).c_str(),
                NULL));
        }
        //else
        virtiofsd_pids.push_back(pid);
    }

    auto pid = fork();
    if (pid < 0) throw std::runtime_error("fork() failed");
    if (pid == 0) { // child process
        char ** argv = new char *[qemu_cmdline.size() + 1];
        for (int i = 0; i < qemu_cmdline.size(); i++) {
            argv[i] = strdup(qemu_cmdline[i].c_str());
        }
        argv[qemu_cmdline.size()] = NULL;
        _exit(execvp(qemu_cmdline[0].c_str(), argv));
    }
    int wstatus;
    waitpid(pid, &wstatus, 0);

    std::cout << "VM ended" << std::endl;
    return WIFEXITED(wstatus)? WEXITSTATUS(wstatus) : -1;
}

void usage(const std::string& progname)
{
    std::cout << "Usage:" << std::endl;
    std::cout << "  " << progname << ' ' << "vmname" << std::endl;
}

int main(int argc, char* argv[])
{
    const std::string progname = argv[0];
    auto args = getopt(argc, argv, {
        {'h', "help", [&progname]() {
            usage(progname);
            exit(-1);
        }},
        {'v', "version", []() {
            std::cout << "vm 0.1" << std::endl;
            exit(-1);
        }},
    });

    if (args.size() != 1) {
        usage(argv[0]);
        exit(-1);
    }

    try {
        return vm(args[0]);
    }
    catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        exit(-1);
    }
}

// g++ -std=c++20 -o vm vm.cpp -liniparser4
