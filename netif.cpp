#include <filesystem>
#include <fstream>
#include <regex>

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
    } else {
        throw std::runtime_error(ifname + " is not a valid network interface name");
    }
}

} // namespace netif