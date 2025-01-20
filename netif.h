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

        typedef std::variant<User,Bridge,Tap,Mcast> Some;
    }

    type::Some to_netif(const std::string& ifname);
}
