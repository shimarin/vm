#ifndef __VSOCK_H__
#define __VSOCK_H__

#include <cstdint>
#include <string>
#include <filesystem>
#include <unistd.h>

namespace vsock {
    uint32_t determine_guest_cid(uid_t uid, const std::string& vmname);
    pid_t run_sock_forward(uint32_t vsock_port, const std::filesystem::path& unix_sock_path);
    // Expose a guest vsock port as <dir>/<socket_name> on the host (the reverse
    // direction of run_sock_forward). The proxy chdir()s to dir so that the run
    // directory path never reaches socat's address parser.
    pid_t run_vsock_export(uint32_t guest_cid, uint32_t vsock_port, const std::filesystem::path& dir, const std::string& socket_name);
} // namespace vsock

#endif // __VSOCK_H__
