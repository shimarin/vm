#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <cstring>

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

} // namespace netif