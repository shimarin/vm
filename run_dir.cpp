#include <sys/file.h>
#include <unistd.h>

#include <optional>
#include <mutex>

#include "run_dir.h"

namespace run_dir {

const std::filesystem::path& xdg_runtime_dir()
{
    static std::filesystem::path xdg_runtime_dir;
    static std::once_flag flag;
    std::call_once(flag, []() {
        xdg_runtime_dir = [](const char* env_var) -> std::filesystem::path {
            return env_var? std::filesystem::path(env_var) : std::filesystem::path("/run/user") / std::to_string(getuid());
        }(getenv("XDG_RUNTIME_DIR"));
    });
    return xdg_runtime_dir;
}

const std::filesystem::path& root()
{
    static std::filesystem::path run_dir;
    static std::once_flag flag;
    std::call_once(flag, []() {
        run_dir = getuid() == 0? "/run/vm" : xdg_runtime_dir() / "vm";
        std::filesystem::create_directories(run_dir);
    });
    return run_dir;
}

int lock_pci(const std::string& pci_id)
{
    auto lock_dir = pci_lock();
    std::filesystem::create_directories(lock_dir);
    auto lock_file = lock_dir / pci_id;

    int fd = open(lock_file.c_str(), O_CREAT | O_RDWR, 0600);
    if (fd < 0) {
        throw std::runtime_error("Failed to create or open lock file");
    }

    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        bool already_locked = errno == EWOULDBLOCK;
        close(fd);
        if (already_locked) return -1;
        else throw std::runtime_error("Failed to lock file");
    }

    return fd;  // lock acquired
}


int lock_vm(const std::string& vmname)
{
    auto dir = vm_dir(vmname);
    std::filesystem::create_directories(dir);
    auto vm_run_dir_fd = open(dir.c_str(), O_RDONLY, 0);
    if (vm_run_dir_fd < 0) throw std::runtime_error(std::string("open(") + dir.string() + ") failed");

    if (flock(vm_run_dir_fd, LOCK_EX|LOCK_NB) < 0) {
        bool already_running = errno == EWOULDBLOCK;
        close(vm_run_dir_fd);
        if (already_running) return -1;
        else throw std::runtime_error(std::string("flock(") + dir.string() + ") failed");
    }
    return vm_run_dir_fd;
}

bool is_running(const std::string& vmname)
{
    auto dir = vm_dir(vmname);
    if (!std::filesystem::exists(dir)) return false;
    //else try flock and return true if EWOULDBLOCK
    auto vm_dir_fd = open(dir.c_str(), O_RDONLY, 0);
    if (vm_dir_fd < 0) throw std::runtime_error(std::string("open(") + dir.string() + ") failed");
    //else
    auto rst = flock(vm_dir_fd, LOCK_EX|LOCK_NB);
    close(vm_dir_fd);
    if (rst < 0) {
        bool running = errno == EWOULDBLOCK;
        close(vm_dir_fd);
        if (running) return true;
        else throw std::runtime_error(std::string("flock(") + dir.string() + ") failed");
    }
    return false;
}

} // namespace run_dir
