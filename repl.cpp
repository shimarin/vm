#include <iostream>

#include <pybind11/embed.h>
#include <pybind11/stl.h>

#include "netif.h"
#include "vsock.h"

int myfunc()
{
    std::cout << "Hello, World!" << std::endl;
    return 0;
}

int repl()
{
    auto builtins = pybind11::module_::import("builtins");
    builtins.attr("myfunc") = pybind11::cpp_function(myfunc);
    builtins.attr("to_netif") = pybind11::cpp_function([](const std::string& ifname) {
        auto rst = netif::to_netif(ifname);
        return std::visit([](auto&& arg) -> std::string {
            using T = std::decay_t<decltype(arg)>;
            if constexpr (std::is_base_of_v<netif::type::_namedif, T>) {
                //return std::format("{}: {}", typeid(T).name(), arg.name);
                return typeid(T).name() + std::string(": ") + arg.name;
            } else if constexpr (std::is_same_v<T, netif::type::User>) {
                return "User";
            } else if constexpr (std::is_same_v<T, netif::type::Mcast>) {
                return "Mcast: " + arg.addr;
                //return std::format("Mcast: {}", arg.addr);
            } else if constexpr (std::is_same_v<T, netif::type::SRIOV>) {
                return "SRIOV: " + arg.pf_name + "(vf" + std::to_string(arg.vf_start) + "-" + std::to_string(arg.vf_start + arg.vf_count - 1) + ")";
            }
            throw std::runtime_error("Unknown type");
        }, rst);
    }, pybind11::arg("ifname"));
    builtins.attr("get_vf_pci_id") = pybind11::cpp_function(netif::get_vf_pci_id, pybind11::arg("ifname"), pybind11::arg("vf_num"));
    builtins.attr("make_interface_up") = pybind11::cpp_function(netif::make_interface_up, pybind11::arg("ifname"));
    builtins.attr("open_macvtap") = pybind11::cpp_function(netif::open_macvtap, pybind11::arg("ifname"));
    builtins.attr("determine_guest_cid") = pybind11::cpp_function([](const std::string& vmname) {
        return vsock::determine_guest_cid(vmname);
    }, pybind11::arg("vmname"));

    pybind11::exec(R"(
import code,readline,rlcompleter
history_file = os.path.expanduser("~/.python_history")
if os.path.exists(history_file):
    readline.read_history_file(history_file)
readline.parse_and_bind("tab: complete")
readline.set_completer(rlcompleter.Completer(globals()).complete)
try:
    code.interact(local=globals())
finally:
    readline.write_history_file(history_file)
)");
    return 0;
}

int main(int argc, char* argv[])
{
    pybind11::scoped_interpreter guard{};
    try {
        return repl();
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    return 0;
}
