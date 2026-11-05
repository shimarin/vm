#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <cstring>
#include <cstdio>

#include <filesystem>
#include <fstream>
#include <regex>
#include <optional>

#include <linux/if_tun.h>

#include "netif.h"

namespace netif {

static std::filesystem::path sysfs = "/sys/class/net";

static bool is_bridge(const std::string& ifname)
{
    auto file_to_test = sysfs / ifname / "bridge";
    return std::filesystem::exists(file_to_test);
}

static bool is_tap(const std::string& ifname)
{
    auto file_to_test = sysfs / ifname / "tun_flags";
    if (!std::filesystem::exists(file_to_test)) {
        return false;
    }
    std::ifstream file(file_to_test);
    std::string line;
    std::getline(file, line);
    // parse line as hex string starts with 0x sign
    std::regex re("0x[0-9a-fA-F]+");
    std::smatch match;
    if (!std::regex_search(line, match, re)) {
        return false;
    }
    auto flags = std::stoul(match.str(), nullptr, 16);
    return flags & IFF_TAP;
}

static bool is_mcast(const std::string& ifname)
{
    // check if ifname is combination of multicast IPv4 address and port number separated by colon
    std::regex re("^(\\d{1,3}\\.){3}\\d{1,3}:[1-9]\\d*$");
    return std::regex_match(ifname, re);
}

static bool is_macvtap(const std::string& ifname)
{
    return std::filesystem::is_directory(sysfs / ifname / "macvtap");
}

static bool is_vde(const std::string& ifname)
{
    return std::filesystem::is_socket(std::filesystem::path(ifname) / "ctl");
}

std::optional<std::string> get_vf_pci_id(const std::string& pf_name, int vf_number)
{
    auto vf_dir = sysfs / pf_name / "device" / ("virtfn" + std::to_string(vf_number));
    if (!std::filesystem::is_directory(vf_dir)) return std::nullopt;
    //else
    auto pci_device_dir = std::filesystem::read_symlink(vf_dir);
    return pci_device_dir.filename().string();
}

static std::optional<std::tuple<std::string,int,int>> get_pf_and_vf_range(const std::string& name)
{
    // VF name ends with vx-y (x and y are numbers between 0 and 999)
    std::regex re_single_vf("(.+)v([0-9]{1,3})$");
    std::smatch match;
    std::string pf_name;
    int vf_starts, vf_ends;
    if (std::regex_search(name, match, re_single_vf)) {
        pf_name = match[1].str();
        vf_starts = std::stoi(match[2]);
        vf_ends = vf_starts;
    } else {
        std::regex re_vf_range("(.+)v([0-9]{1,3})-([0-9]{1,3})$");
        if (!std::regex_search(name, match, re_vf_range)) return std::nullopt;
        pf_name = match[1].str();
        vf_starts = std::stoi(match[2]);
        vf_ends = std::stoi(match[3]);
    }
    auto totalvfs = sysfs / pf_name / "device/sriov_totalvfs";
    std::ifstream f(totalvfs);
    if (!f) return std::nullopt;
    int total;
    f >> total;
    if (vf_ends >= total) return std::nullopt; // vf_end is out of range
    //else
    return std::make_tuple(pf_name, vf_starts, vf_ends - vf_starts + 1);
}

type::Some to_netif(const std::string& ifname)
{
    if (ifname == "user") {
        return type::User();
    } else if (is_bridge(ifname)) {
        return type::Bridge(ifname);
    } else if (is_tap(ifname)) {
        return type::Tap(ifname);
    } else if (is_mcast(ifname)) {
        return type::Mcast(ifname);
    } else if (is_macvtap(ifname)) {
        return type::MACVTAP(ifname);
    } else if (is_vde(ifname)) {
        return type::VDE(std::filesystem::path(ifname));
    }
    //else
    auto sriov_pd_and_vf_range = get_pf_and_vf_range(ifname);
    if (sriov_pd_and_vf_range.has_value()) {
        auto [pf_name, vf_start, vf_count] = sriov_pd_and_vf_range.value();
        return type::SRIOV(pf_name, vf_start, vf_count);
    }
    //else
    throw std::runtime_error(ifname + " is not a valid network interface name");
}

bool make_interface_up(const std::string& ifname)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        throw std::runtime_error("Failed to create socket");
    }
    //else

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);

    // 現在のフラグを取得
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        close(sock);
        throw std::runtime_error("Failed to get interface flags");
    }

    // IFF_UP ビットがすでに立っている場合はfalseを返す
    if (ifr.ifr_flags & IFF_UP) {
        close(sock);
        return false;
    }
    //else
    
    ifr.ifr_flags |= IFF_UP;

    // フラグを設定
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        close(sock);
        throw std::runtime_error("Failed to set interface flags");
    }

    close(sock);
    return true;
}

std::tuple<std::string,int> open_macvtap(const std::string& ifname)
{
    // write "1" to /proc/sys/net/ipv6/conf/<IFNAME>/disable_ipv6 to disable IPv6 on the interface
    {
        std::ofstream ipv6_disable(std::filesystem::path("/proc/sys/net/ipv6/conf") / ifname / "disable_ipv6");
        ipv6_disable << "1";
    }
    make_interface_up(ifname);
    // the mac address is read from /sys/class/net/<ifname>/address
    std::ifstream file(sysfs / ifname / "address");
    std::string macaddr;
    std::getline(file, macaddr);

    // open /dev/tapX (X is read from /sys/class/net/<ifname>/ifindex)
    std::ifstream ifindex_file(sysfs / ifname / "ifindex");
    int ifindex;
    ifindex_file >> ifindex;
    std::string tapdev = "/dev/tap" + std::to_string(ifindex);
    int fd = open(tapdev.c_str(), O_RDWR);
    if (fd < 0) {
        throw std::runtime_error("Failed to open " + tapdev);
    }
    
    return {macaddr, fd};
}

/*
 * MD5 (RFC 1321), used only to derive a stable MAC address from the VM name.
 *
 * Kept here as a private, self-contained implementation: the algorithm must stay MD5
 * because existing MAC addresses (and thus DHCP leases) are derived from it, while the
 * kernel's AF_ALG interface is allow-listed since Linux v7.3 and md5 there requires
 * CAP_NET_ADMIN/CAP_SYS_ADMIN, so calling it from an unprivileged vm fails with ENOENT.
 * Pulling in a crypto library for a single digest is not worth the dependency.
 */
namespace {

constexpr uint32_t md5_K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

constexpr unsigned int md5_S[64] = {
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};

void md5_transform(uint32_t state[4], const uint8_t block[64])
{
    uint32_t m[16];
    for (int i = 0; i < 16; i++) {
        m[i] = (uint32_t)block[i*4] | ((uint32_t)block[i*4+1] << 8)
             | ((uint32_t)block[i*4+2] << 16) | ((uint32_t)block[i*4+3] << 24);
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    for (int i = 0; i < 64; i++) {
        uint32_t f;
        int g;
        if (i < 16)      { f = (b & c) | (~b & d); g = i; }
        else if (i < 32) { f = (d & b) | (~d & c); g = (5*i + 1) & 15; }
        else if (i < 48) { f = b ^ c ^ d;          g = (3*i + 5) & 15; }
        else             { f = c ^ (b | ~d);       g = (7*i) & 15; }

        uint32_t tmp = d;
        d = c;
        c = b;
        uint32_t x = a + f + md5_K[i] + m[g];
        b += (x << md5_S[i]) | (x >> (32 - md5_S[i]));
        a = tmp;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

void md5(const uint8_t* data, size_t length, uint8_t result[16])
{
    uint32_t state[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
    uint8_t block[64];
    uint64_t length_bits = (uint64_t)length * 8;

    while (length >= 64) {
        md5_transform(state, data);
        data += 64;
        length -= 64;
    }

    // The tail block: 0x80, then zeros, then the message length in bits, little endian.
    memcpy(block, data, length);
    size_t used = length + 1;
    block[length] = 0x80;
    if (used > 56) {
        memset(block + used, 0, sizeof(block) - used);
        md5_transform(state, block);
        used = 0;
    }
    memset(block + used, 0, 56 - used);
    for (int i = 0; i < 8; i++) {
        block[56 + i] = (uint8_t)(length_bits >> (i * 8));
    }
    md5_transform(state, block);

    for (int i = 0; i < 4; i++) {
        result[i*4]     = (uint8_t)state[i];
        result[i*4+1]   = (uint8_t)(state[i] >> 8);
        result[i*4+2]   = (uint8_t)(state[i] >> 16);
        result[i*4+3]   = (uint8_t)(state[i] >> 24);
    }
}

} // anonymous namespace

std::string generate_macaddr_from_name(const std::string& vmname, int net_num)
{
    std::string name = vmname + ":" + std::to_string(net_num);
    uint8_t buf[16];
    md5((const uint8_t*)name.c_str(), name.length(), buf);

    // QEMU's registered Ethernet prefix (52:54:00) followed by 23 bits of the digest:
    // the low 7 bits of the first byte (the top bit is masked off) plus the next two bytes
    uint8_t mac[6] = { 0x52, 0x54, 0x00, 0x00, 0x00, 0x00 };
    mac[3] = buf[0] & 0x7f;
    mac[4] = buf[1];
    mac[5] = buf[2];

    char mac_str[18];
    sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", (int)mac[0], (int)mac[1], (int)mac[2], (int)mac[3], (int)mac[4], (int)mac[5]);
    return std::string(mac_str);
}

} // namespace netif
