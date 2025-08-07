#include <string>

namespace pci {
    std::tuple<std::string, bool, bool, std::optional<std::string>> parse_pci_string(const std::string& pci_id);
    bool replace_driver_with_vfio(const std::string& pci_id);
    void acquire_iommu_memory(const std::string& vmname, uint32_t memory_to_newly_allocate_in_mb);
}