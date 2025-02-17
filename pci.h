#include <string>

namespace pci {
    bool replace_driver_with_vfio(const std::string& pci_id);
    int lock_pci_device(const std::string& pci_id); // returns -1 if unanle to acquire lock
}