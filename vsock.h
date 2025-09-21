#ifndef __VSOCK_H__
#define __VSOCK_H__

#include <cstdint>
#include <string>
#include <vector>
#include <unistd.h>

namespace vsock {
    // Function to determine the guest CID based on the VM name
    // Returns the CID as a uint32_t
    uint32_t determine_guest_cid(uid_t uid, const std::string& vmname);
    int ssh(uid_t uid, const std::string& vmname, const std::vector<std::string>& ssh_args);
} // namespace vsock

#endif // __VSOCK_H__
