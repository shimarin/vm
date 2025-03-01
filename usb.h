#include <filesystem>
#include <string>
#include <vector>

void print_usb_devices_xml();
void print_example_query();
std::vector<std::filesystem::path> query_usb_devices(const std::string& xpath);
