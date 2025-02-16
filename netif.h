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
            SRIOV(const std::string& _pci_id) : pci_id(_pci_id) {} 
            std::string pci_id;
        };

        typedef std::variant<User,Bridge,Tap,Mcast,MACVTAP,SRIOV> Some;
    }

    type::Some to_netif(const std::string& ifname);
    bool make_interface_up(const std::string& ifname);
    std::tuple<std::string,int> open_macvtap(const std::string& ifname);
}
