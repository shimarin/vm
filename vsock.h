#ifndef __VSOCK_H__
#define __VSOCK_H__

#include <cstdint>
#include <string>
#include <filesystem>
#include <unistd.h>

namespace vsock {
    uint32_t determine_guest_cid(uid_t uid, const std::string& vmname);
    pid_t run_sock_forward(uint32_t vsock_port, const std::filesystem::path& unix_sock_path);
} // namespace vsock

#endif // __VSOCK_H__
