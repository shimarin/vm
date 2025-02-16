#include <unistd.h>
#include <sys/wait.h>

#include <filesystem>
#include <fstream>
#include <optional>
#include "pci.h"

static std::filesystem::path pci_dir = "/sys/bus/pci";
static auto pci_devices_dir = pci_dir / "devices";
static bool modprobe_done = false;

void modprobe_vfio_pci()
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