#ifndef __VSOCK_H__
#define __VSOCK_H__

#include <cstdint>
#include <string>

namespace vsock {
    // Function to determine the guest CID based on the VM name
    // Returns the CID as a uint32_t
    uint32_t determine_guest_cid(const std::string& vmname);
} // namespace vsock

#endif // __VSOCK_H__
