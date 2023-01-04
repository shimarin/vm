#ifndef __JSON_MESSAGING_H__
#define __JSON_MESSAGING_H__

#include <optional>
#include <nlohmann/json.hpp>

std::optional<nlohmann::json> receive_message(int fd);
void send_message(int fd, const nlohmann::json& message);
std::optional<nlohmann::json> execute_query(int fd, const nlohmann::json& query);

#endif // __JSON_MESSAGING_H__
