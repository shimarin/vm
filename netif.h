#include <string>
#include <variant>

namespace netif {
    namespace type {
        struct User{};
        struct _namedif { 
            std::string name;
            _namedif(const std::string& _name) : name(_name) {} 
        };
        struct Bridge : public _namedif { Bridge(const std::string& _name) : _namedif(_name) {} };
        struct Tap : public _namedif { Tap(const std::string& _name) : _namedif(_name) {} };
        struct Mcast {
            Mcast(const std::string& _addr) : addr(_addr) {} 
            std::string addr;
        };
        struct MACVTAP : public _namedif { MACVTAP(const std::string& _name) : _namedif(_name) {} };
        struct SRIOV {
            SRIOV(const std::string& _pf_name, int _vf_start, int _vf_count) 
                : pf_name(_pf_name), vf_start(_vf_start), vf_count(_vf_count) {}
            std::string pf_name;
            int vf_start, vf_count;
        };
        struct VDE {
            VDE(const std::filesystem::path& _sock_dir) : sock_dir(_sock_dir) {}
            std::filesystem::path sock_dir;
        };

        typedef std::variant<User,Bridge,Tap,Mcast,MACVTAP,SRIOV,VDE> Some;
    }

    type::Some to_netif(const std::string& ifname);
    bool make_interface_up(const std::string& ifname);
    std::tuple<std::string,int> open_macvtap(const std::string& ifname);
    std::optional<std::string> get_vf_pci_id(const std::string& pf_name, int vf_number);
}
