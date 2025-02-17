#include <sys/wait.h>
#include <sys/file.h>
#include <unistd.h>
#include <fcntl.h>

#include <filesystem>
#include <fstream>
#include <optional>
#include "pci.h"

static std::filesystem::path pci_dir = "/sys/bus/pci";
static auto pci_devices_dir = pci_dir / "devices";
static bool modprobe_done = false;

static void modprobe_vfio_pci()
{
    if (modprobe_done) return;
    //else
    auto pid = fork();
    if (pid == 0) {
        execlp("modprobe", "modprobe", "vfio-pci", NULL);
        _exit(1);
    }
    //else
    int wstatus;
    waitpid(pid, &wstatus, 0);
    if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus) != 0) {
        throw std::runtime_error("modprobe vfio-pci failed");
    }
    modprobe_done = true;
}

namespace pci {

bool replace_driver_with_vfio(const std::string& pci_id)
{
    auto driver_dir = pci_devices_dir / pci_id / "driver";

    auto driver = 
        std::filesystem::exists(driver_dir)? 
            std::make_optional(std::filesystem::read_symlink(driver_dir).filename().string()) : std::nullopt;
    if (driver) {
        if (*driver == "vfio-pci") return false; // already bound to vfio-pci
        //else
        std::ofstream unbind(pci_dir / "drivers" / *driver / "unbind");
        unbind << pci_id;
    }
    modprobe_vfio_pci();
    {
        std::ofstream override(pci_devices_dir / pci_id / "driver_override");
        override << "vfio-pci" << std::endl;
    }
    {
        std::ofstream probe(pci_dir / "drivers_probe");
        probe << pci_id << std::endl;
    }
    return true;
}

int lock_pci_device(const std::string& pci_id)
{
    std::filesystem::path lock_dir("/run/vm/.pci-lock");
    std::filesystem::create_directories(lock_dir);
    auto lock_file = lock_dir / pci_id;

    int fd = open(lock_file.c_str(), O_CREAT | O_RDWR, 0600);
    if (fd < 0) {
        throw std::runtime_error("Failed to create or open lock file");
    }

    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        // lock has been already acquired, it seems
        return -1;
    }

    return fd;  // lock acquired
}
} // namespace pci