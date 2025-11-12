#include <filesystem>
#include <functional>

namespace run_dir {
    const std::filesystem::path& xdg_runtime_dir();
    const std::filesystem::path& root();

    inline auto pci_lock() {return root() / ".pci-lock";}
    int lock_pci(const std::string& pci_id);

    int lock_vm(const std::string& vmname);
    bool is_running(const std::string& vmname);

    inline auto vm_dir(const std::string& vmname) {return root() / vmname;}
    inline auto qemu_pid(const std::string& vmname) {return vm_dir(vmname) / "qemu.pid";}
    inline auto qmp_sock(const std::string& vmname) {return vm_dir(vmname) / "qmp.sock";}
    inline auto monitor_sock(const std::string& vmname) {return vm_dir(vmname) / "monitor.sock";}
    inline auto console_sock(const std::string& vmname) {return vm_dir(vmname) / "console.sock";}
    inline auto qga_sock(const std::string& vmname) {return vm_dir(vmname) / "qga.sock";}
    inline auto qga_lock(const std::string& vmname) {return vm_dir(vmname) / "qga.lock";}
    inline auto virtiofs_sock(const std::string& vmname) {return vm_dir(vmname) / "virtiofs.sock";}
    inline auto iommu_mem(const std::string& vmname) {return vm_dir(vmname) / "iommu-mem";}

    template <typename T>
    inline std::vector<T> for_each_running_vms(std::function<T(const std::string&)> f) {
        std::vector<T> ret;
        for (const auto& p : std::filesystem::directory_iterator(root())) {
            if (!p.is_directory()) continue;
            auto name = p.path().filename().string();
            if (name[0] == '.') continue;
            if (is_running(name)) {
                ret.push_back(f(name));
            }
        }
        return ret;
    }
} // namespace run_dir