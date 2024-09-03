/*
 * mirrortap.cpp
 * LICENSE: MIT
 * Created by: Tomoatsu Shimada <shimada@walbrix.com>
*/
#include <sys/wait.h>
#include <unistd.h>

#include <vector>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <argparse/argparse.hpp>

int run_command(const std::vector<std::string>& cmdline)
{
    // fork and execvp the command
    pid_t pid = fork();
    if (pid == -1) {
        throw std::runtime_error("Failed to fork");
    }
    if (pid == 0) {
        std::vector<char*> argv;
        for (const auto& arg : cmdline) {
            argv.push_back(const_cast<char*>(arg.c_str()));
        }
        argv.push_back(nullptr);
        execvp(argv[0], argv.data());
        // if execvp returns, it failed
        std::cerr << "Failed to execvp " << argv[0] << std::endl;
        exit(1);
    }
    //else
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

void create_tap_if_not_exists(const std::string& tapname)
{
    auto sys_tap = std::filesystem::path("/sys/class/net") / tapname;
    if (std::filesystem::exists(sys_tap)) {
        auto tun_flags = sys_tap / "tun_flags";
        if (![&tun_flags](){
            if (!std::filesystem::is_regular_file(tun_flags)) return false;
            //else
            std::ifstream ifs(tun_flags); // file contains hex flags starts with 0x
            int flags;
            ifs >> std::hex >> flags;
            return (bool)(flags & 0x0002);
        }()) {
            throw std::runtime_error("Device already exists and not a tap device");
        }
        return;
    } 
    //else
    if (run_command({"ip", "tuntap", "add", "mode", "tap", tapname}) != 0) {
        throw std::runtime_error("Failed to create tap interface");
    }
    // else 
    if (run_command({"ip", "link", "set", "dev", tapname, "up"}) != 0) {
        throw std::runtime_error("Failed to bring up tap interface");
    }
}

void configure_mirror(const std::string& srcif, const std::string& dstif)
{
    auto success =
        run_command({"tc","qdisc","add","dev",srcif,"handle","ffff:","ingress"}) == 0
        && run_command({"tc","filter","add","dev",srcif,"parent","ffff:","protocol","all","u32","match","u8","0","0","action","mirred","egress","mirror","dev",dstif}) == 0
        && run_command({"tc","qdisc","add","dev",srcif,"handle","1:","root","prio"}) == 0
        && run_command({"tc","filter","add","dev",srcif,"parent","1:","protocol","all","u32","match","u8","0","0","action","mirred","egress","mirror","dev",dstif}) == 0;

    if (!success) {
        throw std::runtime_error("Failed to configure mirroring");
    }
}

void make_source_promiscuous(const std::string& srcif)
{
    if (run_command({"ip", "link", "set", "dev", srcif, "promisc", "on"}) != 0) {
        throw std::runtime_error("Failed to set source interface to promiscuous mode");
    }
}

int main(int argc, char* argv[])
{
    argparse::ArgumentParser program("mirrortap");
    program.add_argument("srcif:dstif").help("Source and destination interface names");

    try {
        program.parse_args(argc, argv);
        
    } catch (const std::runtime_error& err) {
        std::cout << err.what() << std::endl;
        std::cout << program;
        return 1;
    }
    auto srcdst = program.get<std::string>("srcif:dstif");
    auto sep = srcdst.find(':');
    if (sep == std::string::npos) {
        std::cerr << "Invalid argument: " << srcdst << std::endl;
        return 1;
    }
    //else
    std::string srcif = srcdst.substr(0, sep);
    std::string dstif = srcdst.substr(sep+1);

    try {
        if (getuid() != 0) {
            throw std::runtime_error("This program must be run as root");
        }
        create_tap_if_not_exists(dstif);
        configure_mirror(srcif, dstif);
        make_source_promiscuous(srcif);
    }
    catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    std::cout << "Mirroring " << srcif << " to " << dstif << std::endl;
    return 0;
}
