#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/usbdevice_fs.h>
#include <linux/usb/ch9.h>

#include <iostream>
#include <memory>
#include <optional>

#include <iconv.h>
#include <libxml++/libxml++.h>

#include "usb.h"

// Helper function to convert uint16_t to hex string
std::string to_hex(uint16_t value) {
    std::ostringstream oss;
    oss << std::hex << std::setw(4) << std::setfill('0') << value;
    return oss.str();
}

// Helper function to convert UTF-16LE to UTF-8
static std::string convert_utf16le_to_utf8(const uint8_t* utf16_data, size_t len) {
    iconv_t cd = iconv_open("UTF-8", "UTF-16LE");
    if (cd == (iconv_t)-1) {
        return "";
    }

    // skip BOM
    uint8_t* inbuf = const_cast<uint8_t*>(utf16_data) + 2;
    size_t inbytesleft = len - 2;
    std::vector<char> outbuf(inbytesleft * 4); // maximum 4 bytes per character
    char* outptr = outbuf.data();
    size_t outbytesleft = outbuf.size();

    iconv(cd, (char**)&inbuf, &inbytesleft, &outptr, &outbytesleft);
    iconv_close(cd);

    return std::string(outbuf.data(), outbuf.size() - outbytesleft);
}

// function to get string descriptor
static std::optional<std::string> get_string_descriptor(int fd, uint8_t index) {
    if (index == 0) return std::nullopt;

    struct usbdevfs_ctrltransfer ctrl = {
        .bRequestType = USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_DEVICE,
        .bRequest = USB_REQ_GET_DESCRIPTOR,
        .wValue = (uint16_t)((USB_DT_STRING << 8) | index),
        .wIndex = 0, // language ID (0 = default)
        .wLength = 255,
        .timeout = 5000,
        .data = malloc(255)
    };

    int ret = ioctl(fd, USBDEVFS_CONTROL, &ctrl);
    if (ret < 0) {
        free(ctrl.data);
        return std::nullopt;
    }

    // get first byte of the string descriptor to determine the length
    unsigned char* data = static_cast<unsigned char*>(ctrl.data);
    size_t length = data[0]; // bLength is the number of bytes
    std::string result = convert_utf16le_to_utf8(data, length);

    free(ctrl.data);
    return result;
}

struct USBDeviceProperties {
    uint16_t vendor_id;
    uint16_t product_id;
    uint16_t device_revision;
    uint8_t device_class;
    uint8_t device_subclass;
    std::optional<std::string> vendor_name;
    std::optional<std::string> product_name;
};

static std::optional<USBDeviceProperties> get_usb_device_properties(const std::string& device_path) {
    USBDeviceProperties properties = {};

    // Control transfer to get device descriptor
    struct usbdevfs_ctrltransfer ctrl = {
        .bRequestType = USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_DEVICE,
        .bRequest = USB_REQ_GET_DESCRIPTOR,
        .wValue = USB_DT_DEVICE << 8, // specify device descriptor
        .wIndex = 0,
        .wLength = USB_DT_DEVICE_SIZE, // size of device descriptor
        .timeout = 5000, // Timeout in milliseconds
        .data = malloc(USB_DT_DEVICE_SIZE)
    };
    int fd = open(device_path.c_str(), O_RDWR);
    if (fd < 0) {
        free(ctrl.data);
        return std::nullopt;
    }
    if (ioctl(fd, USBDEVFS_CONTROL, &ctrl) < 0) {
        free(ctrl.data);
        close(fd);
        throw std::runtime_error("Failed to get device descriptor");
    }
    auto device_descriptor = reinterpret_cast<struct usb_device_descriptor*>(ctrl.data);
    properties.vendor_id = device_descriptor->idVendor;
    properties.product_id = device_descriptor->idProduct;
    properties.device_revision = device_descriptor->bcdDevice;
    properties.device_class = device_descriptor->bDeviceClass;
    properties.device_subclass = device_descriptor->bDeviceSubClass;

    // Get string descriptors
    properties.vendor_name = get_string_descriptor(fd, device_descriptor->iManufacturer);
    properties.product_name = get_string_descriptor(fd, device_descriptor->iProduct);

    free(ctrl.data);
    close(fd);
    return properties;
}

static bool looks_like_a_root_hub(const USBDeviceProperties& properties) {
    return properties.device_class == 9 && properties.vendor_id == 0x1d6b;
}

static std::shared_ptr<xmlpp::Document> get_usb_devices_xml()
{
    auto doc = std::shared_ptr<xmlpp::Document>(new xmlpp::Document());
    auto root_element = doc->create_root_node("usb");

    if (!std::filesystem::exists("/dev/bus/usb")) throw std::runtime_error("USB device not found");
    //else
    // enumerate USB devices
    for (const auto& bus_entry : std::filesystem::directory_iterator("/dev/bus/usb"))
    {
        auto bus_element = root_element->add_child_element("bus");
        bus_element->set_attribute("path", bus_entry.path().string());
        auto bus_id = bus_entry.path().filename().string();
        bus_element->set_attribute("id", bus_id);

        for (const auto& device_entry : std::filesystem::directory_iterator(bus_entry.path()))
        {
            auto device_path = device_entry.path().string();
            auto device_id = device_entry.path().filename().string();
            auto device_properties = get_usb_device_properties(device_path);
            if (!device_properties || looks_like_a_root_hub(*device_properties)) continue; // skip root hubs
            auto device_element = bus_element->add_child_element("device");
            device_element->set_attribute("path", device_path);
            device_element->set_attribute("id", bus_id + ":" + device_id);
            device_element->set_attribute("bus_id", std::to_string(std::stoi(bus_id)));
            device_element->set_attribute("device_id", std::to_string(std::stoi(device_id)));
            device_element->set_attribute("vendor_id", to_hex(device_properties->vendor_id));
            device_element->set_attribute("product_id", to_hex(device_properties->product_id));
            device_element->set_attribute("device_revision", to_hex(device_properties->device_revision));
            device_element->set_attribute("device_class", std::to_string(device_properties->device_class));
            device_element->set_attribute("device_subclass", std::to_string(device_properties->device_subclass));
            if (device_properties->vendor_name)
                device_element->set_attribute("vendor_name", *device_properties->vendor_name);
            if (device_properties->product_name)
                device_element->set_attribute("product_name", *device_properties->product_name);
        }
    }

    return doc;
}

static std::vector<std::filesystem::path> query_usb_devices(std::shared_ptr<xmlpp::Document> doc, const std::string& xpath)
{
    std::vector<std::filesystem::path> result;
    auto nodes = doc->get_root_node()->find(xpath);
    for (const auto& node : nodes)
    {
        auto element = dynamic_cast<xmlpp::Element*>(node);
        if (!element) continue;
        // skip other than device elements
        if (element->get_name() != "device") continue;
        auto path = std::filesystem::path(element->get_attribute_value("path"));
        result.push_back(path);
    }
    return result;
}

std::vector<std::filesystem::path> query_usb_devices(const std::string& xpath)
{
    auto doc = get_usb_devices_xml();
    return query_usb_devices(doc, xpath);
}

void print_usb_devices_xml()
{
    get_usb_devices_xml()->write_to_stream_formatted(std::cout);
}

void print_example_query()
{
    std::cout << "\nQEMU devices: //device[contains(@vendor_name, 'QEMU')]" << std::endl;
    std::cout << "\nHubs: //device[@device_class='9']" << std::endl;
}