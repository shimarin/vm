#include <sys/wait.h>
#include <sys/file.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include <filesystem>
#include <fstream>
#include <optional>
#include <numeric>

#include "run_dir.h"
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

void acquire_iommu_memory(const std::string& vmname, uint32_t memory_to_newly_allocate_in_mb)
{
    struct sysinfo info;
    if (sysinfo(&info) < 0) throw std::runtime_error("sysinfo() failed");
    auto physical_memory_size_in_mb = static_cast<uint64_t>(info.totalram) * info.mem_unit / 1024 / 1024;

    auto iommu_mems = run_dir::for_each_running_vms<unsigned long>([](const std::string& vmname) {
        auto fd = open(run_dir::iommu_mem(vmname).c_str(), O_RDONLY);
        if (fd < 0) return (unsigned long)0;
        flock(fd, LOCK_SH);
        char buf[32];
        read(fd, buf, sizeof(buf));
        close(fd);
        return std::stoul(buf);
    });
    auto iommu_mem_total = std::accumulate(iommu_mems.begin(), iommu_mems.end(), 0UL);
    if (iommu_mem_total + memory_to_newly_allocate_in_mb > physical_memory_size_in_mb - 2048) {
        throw std::runtime_error("IOMMU memory limit exceeded. Requested: " 
            + std::to_string(memory_to_newly_allocate_in_mb) + "MB, Available: " 
            + std::to_string(physical_memory_size_in_mb - iommu_mem_total - 2048) + "MB");
    }
    //else
    auto fd = open(run_dir::iommu_mem(vmname).c_str(), O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd < 0) throw std::runtime_error("Failed to create iommu-mem file for " + vmname);
    // lock the file
    flock(fd, LOCK_EX);
    char buf[32];
    snprintf(buf, sizeof(buf), "%u", memory_to_newly_allocate_in_mb);
    write(fd, buf, strlen(buf));
    close(fd);
}

} // namespace pci