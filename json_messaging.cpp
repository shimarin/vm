#include <iostream>
#include <vector>

#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <nlohmann/json.hpp>

#include "json_messaging.h"

std::optional<nlohmann::json> receive_message(int fd)
{
    std::string message;
    while (true) {
        struct pollfd pollfds[1];
        pollfds[0].fd = fd;
        pollfds[0].events = POLLIN;
        if (poll(pollfds, 1, 200) < 0) throw std::runtime_error("poll() failed");
        if (pollfds[0].revents & POLLIN) {
            char c;
            auto n = read(fd, &c, sizeof(c));
            if (n < 1) throw std::runtime_error("Error receiving message via socket");
            if (c == '\n') break;
            //else
            message += c;
        } else {
            return std::nullopt;
        }
    }
    return nlohmann::json::parse(message);
}

void send_message(int fd, const nlohmann::json& message)
{
    auto message_str = message.dump() + '\n';
    if (write(fd, message_str.c_str(), message_str.length()) < 0) {
        throw std::runtime_error("Error sending message via socket");
    }
}

std::optional<nlohmann::json> execute_query(int fd, const nlohmann::json& query)
{
    send_message(fd, query);
    return receive_message(fd);
}

#ifdef __VSCODE_ACTIVE_FILE__
int main(int argc, char* argv[])
{
    struct sockaddr_un sockaddr;
    memset(&sockaddr, 0, sizeof(sockaddr));
    auto sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) throw std::runtime_error("socket() failed");
    sockaddr.sun_family = AF_UNIX;
    strcpy(sockaddr.sun_path, "/run/user/1000/vm/samba/qmp.sock");
    if (connect(sock, (const struct sockaddr *)&sockaddr, sizeof(sockaddr)) < 0) {
        close(sock);
        return -1;
    }
    //else

    auto j = receive_message(sock);
    std::cout << j.value().dump() << std::endl;
    std::cout << j.value()["QMP"]["version"]["qemu"]["minor"].get<int>() << std::endl;

    auto j2 = execute_query(sock, nlohmann::json::parse("{\"execute\":\"qmp_capabilities\"}"));
    std::cout << j2.value().dump() << std::endl;

    auto j3 = execute_query(sock, nlohmann::json::parse("{ \"execute\": \"system_powerdown\"}"));
    std::cout << j3.value().dump() << std::endl;

    shutdown(sock, SHUT_WR);
    close(sock);
    return 0;
}
#endif