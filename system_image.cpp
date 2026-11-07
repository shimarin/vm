#include "system_image.h"

#include <algorithm>
#include <charconv>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace system_image {
    namespace {
        constexpr int mount_timeout_ms = 10000;
        constexpr int unmount_timeout_ms = 5000;
        constexpr int poll_interval_ms = 20;

        // Blocks SIGCHLD for as long as a child is started and waited for, so that
        // waitpid() can always report how it died; the vm's own loop reaps children
        // through signalfd and would otherwise get there first.
        class hold_sigchld {
            sigset_t previous;
        public:
            hold_sigchld()
            {
                sigset_t mask;
                sigemptyset(&mask);
                sigaddset(&mask, SIGCHLD);
                if (sigprocmask(SIG_BLOCK, &mask, &previous) != 0) throw std::runtime_error("sigprocmask() failed");
            }
            ~hold_sigchld() { sigprocmask(SIG_SETMASK, &previous, nullptr); }
            const sigset_t& previous_mask() const { return previous; }
        };

        std::string describe_child_exit(int status)
        {
            if (WIFEXITED(status)) return "exited with status " + std::to_string(WEXITSTATUS(status));
            if (WIFSIGNALED(status)) return "killed by signal " + std::to_string(WTERMSIG(status));
            return "stopped";
        }

        // /proc/self/mounts writes an octal escape for whitespace and backslashes,
        // which is what lets a VM name containing a space be recognized.
        std::string unescape_mount_field(const std::string& field)
        {
            std::string out;
            for (size_t i = 0; i < field.size(); i++) {
                if (field[i] == '\\' && i + 3 < field.size()
                    && field[i + 1] >= '0' && field[i + 1] <= '7'
                    && field[i + 2] >= '0' && field[i + 2] <= '7'
                    && field[i + 3] >= '0' && field[i + 3] <= '7') {
                    auto octal = field.substr(i + 1, 3);
                    out += static_cast<char>(std::stoi(octal, nullptr, 8));
                    i += 3;
                } else out += field[i];
            }
            return out;
        }

        bool is_mounted(const std::filesystem::path& mountpoint)
        {
            std::ifstream mounts("/proc/self/mounts");
            if (mounts.fail()) return false; // there is no other way to look, and the
                                             // callers all time out on a "not mounted"
            std::string line;
            while (std::getline(mounts, line)) {
                // each line is "device mountpoint type options dumpfreq passno", so the
                // fields have to be taken a line at a time rather than off the stream
                std::istringstream fields(line);
                std::string device, path, type;
                if (!(fields >> device >> path >> type)) continue;
                //else
                if (unescape_mount_field(path) == mountpoint.string()) return true;
            }
            return false;
        }

        bool wait_for_mount_state(const std::filesystem::path& mountpoint, bool mounted, int timeout_ms)
        {
            for (int elapsed = 0; elapsed <= timeout_ms; elapsed += poll_interval_ms) {
                if (is_mounted(mountpoint) == mounted) return true;
                usleep(poll_interval_ms * 1000);
            }
            return false;
        }

        // squashfuse has no use for the fds this process holds, and one of them is the
        // lock on the VM's run directory, whose flock would otherwise stay held for as
        // long as the mount lives.
        void close_inherited_fds(int keep)
        {
            if (auto dir = opendir("/proc/self/fd")) {
                while (auto entry = readdir(dir)) {
                    auto fd = atoi(entry->d_name);
                    if (fd > STDERR_FILENO && fd != keep) close(fd);
                }
                closedir(dir);
            }
        }

        // squashfuse is run in the foreground (-f): it stays a child of this process,
        // which is what lets PR_SET_PDEATHSIG and ~ro_mount reach it, while a
        // daemonized one would slip past both.  As with the proxies in vsock.cpp, the
        // child reports a failed exec back through a close-on-exec pipe: a successful
        // exec closes the write end and the parent reads EOF, a failed one delivers
        // the errno.  SIGCHLD stays blocked so that the caller can waitpid() the pid.
        pid_t run_squashfuse(const std::filesystem::path& image, const std::filesystem::path& mountpoint,
            const std::string& options, const sigset_t& previous_mask)
        {
            int handshake[2];
            if (pipe2(handshake, O_CLOEXEC) < 0)
                throw std::runtime_error(std::string("pipe2() failed: ") + strerror(errno));

            auto parent = getpid();
            auto pid = fork();
            if (pid < 0) {
                close(handshake[0]); close(handshake[1]);
                throw std::runtime_error("fork() failed");
            }
            if (pid == 0) {
                auto die = [&](int err) {
                    ssize_t w = write(handshake[1], &err, sizeof(err));
                    (void)w;
                    _exit(127);
                };
                close(handshake[0]);
                if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0) die(errno);
                if (getppid() != parent) die(ESHUTDOWN); // the parent died before prctl() took effect
                sigset_t child_mask = previous_mask;
                sigdelset(&child_mask, SIGCHLD); // the block is ours to hold, not squashfuse's to inherit
                sigprocmask(SIG_SETMASK, &child_mask, nullptr);
                close_inherited_fds(handshake[1]);
                execlp("squashfuse", "squashfuse", "-f", "-o", options.c_str(),
                    image.c_str(), mountpoint.c_str(), static_cast<char*>(nullptr));
                die(errno);
            }

            close(handshake[1]);
            auto err = 0;
            auto r = read(handshake[0], &err, sizeof(err)); // blocks until exec succeeds (EOF) or the child reports
            close(handshake[0]);
            if (r != 0) {
                waitpid(pid, nullptr, 0);
                std::string reason = r != (ssize_t)sizeof(err)? "the process terminated immediately"
                    : err == ENOENT? "squashfuse is not installed" : strerror(err);
                throw std::runtime_error("Failed to start squashfuse: " + reason);
            }
            return pid;
        }

        // Whichever fusermount squashfuse's libfuse used is the one that owns the
        // mount, and hosts built against fuse2 exist, so try both.  A program that is
        // not installed is told apart by the exit status 127 this file's children use.
        bool request_unmount(const std::filesystem::path& mountpoint)
        {
            for (const char* program : {"fusermount3", "fusermount"}) {
                hold_sigchld sigchld;
                auto pid = fork();
                if (pid < 0) throw std::runtime_error("fork() failed");
                if (pid == 0) {
                    execlp(program, program, "-u", mountpoint.c_str(), static_cast<char*>(nullptr));
                    _exit(127);
                }
                int status = 0;
                waitpid(pid, &status, 0);
                if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return true;
                if (WIFEXITED(status) && WEXITSTATUS(status) != 127) return false;
            }
            return false;
        }

        // A mount that has just been released can leave the directory it was in
        // unreachable for a moment, and these directories are only ever empty, so
        // retry for a while and then let it go rather than fail over it.
        void remove_mount_directory(const std::filesystem::path& dir)
        {
            for (int elapsed = 0; elapsed <= unmount_timeout_ms; elapsed += poll_interval_ms) {
                std::error_code ec;
                std::filesystem::remove(dir, ec);
                if (!ec) return;
                usleep(poll_interval_ms * 1000);
            }
        }

        // Reads size bytes at offset into buffer and returns how many were read.
        ssize_t read_at(const std::filesystem::path& file, off_t offset, void* buffer, size_t size)
        {
            auto fd = open(file.c_str(), O_RDONLY);
            if (fd < 0) throw std::runtime_error("open(" + file.string() + ") failed: " + std::string(strerror(errno)));
            //else
            auto r = pread(fd, buffer, size, offset);
            close(fd);
            if (r < 0) throw std::runtime_error("pread(" + file.string() + ") failed: " + std::string(strerror(errno)));
            return r;
        }

        // gunzip -c, reading source from offset and writing to destination.  The
        // payload of an EFI zboot image is not a complete gzip file (the PE stub is
        // still behind it), so its caller accepts a gunzip that complains.
        void unpack_gzip(const std::filesystem::path& source, const std::filesystem::path& destination,
            off_t offset, bool tolerate_trailing_data)
        {
            std::filesystem::create_directories(destination.parent_path());
            auto out = open(destination.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (out < 0) throw std::runtime_error("open(" + destination.string() + ") failed: " + std::string(strerror(errno)));

            hold_sigchld sigchld;
            auto pid = fork();
            if (pid < 0) {
                close(out);
                throw std::runtime_error("fork() failed");
            }
            if (pid == 0) {
                auto in = open(source.c_str(), O_RDONLY);
                if (in >= 0 && offset > 0 && lseek(in, offset, SEEK_SET) < 0) {
                    close(in);
                    in = -1;
                }
                if (in < 0) _exit(125); // a code gunzip(1) itself does not use
                //else
                dup2(in, STDIN_FILENO);
                dup2(out, STDOUT_FILENO);
                close(in);
                close(out);
                execlp("gunzip", "gunzip", "-c", static_cast<char*>(nullptr));
                _exit(127); // the status this file's children use for a program that is not there
            }
            close(out);

            int status = 0;
            waitpid(pid, &status, 0);
            if (WIFEXITED(status) && WEXITSTATUS(status) == 127)
                throw std::runtime_error("gunzip is not installed; needed to unpack " + source.string());
            if (WIFEXITED(status) && WEXITSTATUS(status) == 125)
                throw std::runtime_error("Cannot read " + source.string());
            if (!tolerate_trailing_data && (!WIFEXITED(status) || WEXITSTATUS(status) != 0))
                throw std::runtime_error("Failed to unpack " + source.string() + ": gunzip " + describe_child_exit(status));
        }

        // The names genpack's own mkimage step writes in /boot come first, then the
        // ones a distribution kernel package installs.
        std::pair<std::filesystem::path, std::optional<std::filesystem::path>>
        find_kernel_and_initramfs(const std::filesystem::path& root)
        {
            auto boot_dir = root / "boot";
            if (!std::filesystem::is_directory(boot_dir)) throw std::runtime_error("No boot directory in " + root.string());
            //else
            std::optional<std::filesystem::path> kernel, initramfs;
            if (std::filesystem::is_regular_file(boot_dir / "kernel")) kernel = boot_dir / "kernel";
            else if (std::filesystem::is_regular_file(boot_dir / "vmlinuz")) kernel = boot_dir / "vmlinuz";

            if (kernel) {
                for (const auto& name : {"initramfs", "initramfs.img", "initrd.img"})
                    if (std::filesystem::is_regular_file(boot_dir / name)) { initramfs = boot_dir / name; break; }
                return {*kernel, initramfs};
            }
            //else
            // find "kernel-*" and "vmlinuz-*" under boot_dir and the latest one
            std::filesystem::file_time_type timestamp = std::filesystem::file_time_type::min();
            for (const auto& entry : std::filesystem::directory_iterator(boot_dir)) {
                if (!entry.is_regular_file()) continue;
                auto name = entry.path().filename().string();
                if (!name.starts_with("kernel-") && !name.starts_with("vmlinuz-")) continue;
                auto entry_timestamp = std::filesystem::last_write_time(entry);
                if (entry_timestamp > timestamp) {
                    kernel = entry.path();
                    timestamp = entry_timestamp;
                }
            }
            if (!kernel) throw std::runtime_error("No kernel found in " + boot_dir.string());
            //else
            auto suffix = kernel->filename().string().substr(kernel->filename().string().find("-"));
            for (const auto& name : {"initramfs" + suffix, "initramfs" + suffix + ".img", "initrd.img" + suffix})
                if (std::filesystem::is_regular_file(boot_dir / name)) { initramfs = boot_dir / name; break; }

            return {*kernel, initramfs};
        }
    } // namespace

    ro_mount::ro_mount(const std::filesystem::path& image, const std::filesystem::path& mountpoint)
    {
        if (is_mounted(mountpoint))
            throw std::runtime_error("Something is already mounted at " + mountpoint.string());

        std::filesystem::create_directories(mountpoint);

        // fsname= is what mount(8) and findmnt(8) show as the device; without it
        // every VM would show squashfuse's own name.  A file name with a comma or an
        // equals sign in it would confuse the option list, so it is left out then.
        auto options = std::string("auto_unmount");
        auto name = image.filename().string();
        if (name.find_first_of(",=") == std::string::npos) options += ",fsname=" + name;

        hold_sigchld sigchld;
        pid = run_squashfuse(image, mountpoint, options, sigchld.previous_mask());
        for (int elapsed = 0; elapsed <= mount_timeout_ms; elapsed += poll_interval_ms) {
            int status = 0;
            if (waitpid(pid, &status, WNOHANG) == pid) {
                this->pid = -1;
                remove_mount_directory(mountpoint);
                throw std::runtime_error("Failed to mount " + image.string() + " at " + mountpoint.string()
                    + " with -o " + options + ": squashfuse " + describe_child_exit(status)
                    + " (its own message is above)");
            }
            if (is_mounted(mountpoint)) {
                this->mountpoint = mountpoint;
                return;
            }
            usleep(poll_interval_ms * 1000);
        }
        // squashfuse neither mounted anything nor gave up: give up on it ourselves so
        // that neither it nor an empty directory is left behind.
        kill(pid, SIGKILL);
        waitpid(pid, nullptr, 0);
        this->pid = -1;
        remove_mount_directory(mountpoint);
        throw std::runtime_error("Timed out mounting " + image.string() + " at " + mountpoint.string());
    }

    // Lets go of the mount this object holds: stops squashfuse, makes sure the mount
    // is gone and removes the empty directory it was in.  A mount that cannot be
    // unmounted is reported along with the command that would remove it, because
    // there is nothing else to be done about it here.
    void ro_mount::release() noexcept
    {
        if (pid < 0) return;

        try {
            hold_sigchld sigchld;
            kill(pid, SIGTERM);
            waitpid(pid, nullptr, 0);
            pid = -1;

            bool unmounted = wait_for_mount_state(mountpoint, false, unmount_timeout_ms);
            if (!unmounted) {
                // auto_unmount should have taken care of it; if it did not, ask
                // fusermount rather than leave a dead mount in the VM's run directory
                request_unmount(mountpoint);
                unmounted = wait_for_mount_state(mountpoint, false, unmount_timeout_ms);
            }
            if (!unmounted) {
                std::cerr << "Failed to unmount the system image at " << mountpoint.string()
                    << "; remove it with: fusermount3 -u " << mountpoint.string() << std::endl;
                return;
            }
            //else
            remove_mount_directory(mountpoint); // the empty directory the mount was in
        } catch (const std::exception& e) {
            std::cerr << "Failed to unmount the system image at " << mountpoint.string() << ": " << e.what() << std::endl;
        }
    }

    ro_mount::~ro_mount() { release(); }

    ro_mount::ro_mount(ro_mount&& other) noexcept : pid(other.pid), mountpoint(std::move(other.mountpoint))
    {
        other.pid = -1;
    }

    ro_mount& ro_mount::operator=(ro_mount&& other) noexcept
    {
        if (this != &other) {
            release(); // let go of the mount this one is holding first
            pid = other.pid;
            mountpoint = std::move(other.mountpoint);
            other.pid = -1;
        }
        return *this;
    }

    void ro_mount::sweep_stale(const std::filesystem::path& mountpoint)
    {
        if (!is_mounted(mountpoint)) {
            // nothing mounted: what is there, if anything, is a directory left by a
            // previous run that the next mount would only be in the way of
            std::filesystem::remove_all(mountpoint);
            return;
        }
        //else
        std::cerr << "Unmounting the system image left mounted at " << mountpoint.string() << " by a VM that was killed." << std::endl;
        request_unmount(mountpoint);
        if (is_mounted(mountpoint)) // judged by the mount table, not by fusermount's exit status
            throw std::runtime_error("Failed to unmount the system image left at " + mountpoint.string()
                + "; remove it with: fusermount3 -u " + mountpoint.string());
        remove_mount_directory(mountpoint);
    }

    bool ro_mount::check_auto_unmount()
    {
        if (pid < 0) throw std::runtime_error("The system image is not mounted");

        {
            hold_sigchld sigchld;
            // SIGKILL rather than SIGTERM: what is being checked is that the mount
            // goes away when the process dies, not when it is asked to stop
            kill(pid, SIGKILL);
            waitpid(pid, nullptr, 0);
            pid = -1; // release() must not wait for it, and has no directory to remove
        }

        bool honoured = wait_for_mount_state(mountpoint, false, unmount_timeout_ms);
        if (!honoured) {
            // An older fusermount accepts the option and ignores it: take the mount
            // down ourselves.  Whether that worked is judged by the mount table
            // rather than by what fusermount reports, and a mount still there is
            // reported instead of treating the scratch directory as free, because
            // such a mount outlives this process.
            request_unmount(mountpoint); // fusermount3, or fusermount on a fuse2 host
            if (!wait_for_mount_state(mountpoint, false, unmount_timeout_ms))
                throw std::runtime_error("Failed to unmount the system image mounted at " + mountpoint.string()
                    + "; remove it with: fusermount3 -u " + mountpoint.string());
        }

        remove_mount_directory(mountpoint);
        return honoured;
    }

    metadata::metadata(std::filesystem::path ro_root) : dir(ro_root / ".genpack") {}

    std::optional<std::string> metadata::read_key(const std::string& key, std::string& problem) const
    {
        // The names under /.genpack/ are whatever the image was built with, so none of
        // them is opened through a symbolic link - an absolute link in an image would
        // resolve on the host, and read a host file under the image's account - and none
        // is opened in blocking mode, since a FIFO with no writer would stop vm before the
        // VM starts.  Opening the directory once and the key relative to it puts the same
        // limit on both levels of the path.
        auto dirfd = open(dir.c_str(), O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
        if (dirfd < 0) {
            if (errno == ENOENT) return std::nullopt; // an image with no /.genpack at all
            problem = "open(" + dir.string() + ") failed: " + std::string(strerror(errno));
            return std::nullopt;
        }

        auto path = dir / key;
        // Says what is wrong with the key, and lets go of the directory only where this
        // still holds it: closing one descriptor twice would release a descriptor that
        // something else may have opened in the meantime.
        auto fail = [&](const std::string& why) {
            problem = path.string() + ": " + why;
            return std::optional<std::string>();
        };
        auto fail_holding_dir = [&](const std::string& why) {
            close(dirfd);
            return fail(why);
        };

        struct stat st;
        if (fstat(dirfd, &st) < 0) {
            auto e = errno;
            return fail_holding_dir(std::string("the directory holding it could not be examined: ") + strerror(e));
        }
        if (!S_ISDIR(st.st_mode)) return fail_holding_dir("the directory holding it is not a directory");

        auto fd = openat(dirfd, key.c_str(), O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
        close(dirfd);
        if (fd < 0) {
            if (errno == ENOENT) return std::nullopt; // this image has no such key
            if (errno == ELOOP) return fail("is a symbolic link, which is not followed");
            return fail(std::string("open failed: ") + strerror(errno));
        }

        if (fstat(fd, &st) < 0) {
            auto e = errno;
            close(fd);
            return fail(std::string("could not be examined: ") + strerror(e));
        }
        if (!S_ISREG(st.st_mode)) {
            close(fd);
            return fail("is not a regular file");
        }

        std::string content;
        char buffer[4096];
        for (;;) {
            auto r = read(fd, buffer, sizeof(buffer));
            if (r == 0) break;
            if (r < 0) {
                auto e = errno;
                close(fd);
                return fail(std::string("read failed: ") + strerror(e));
            }
            content.append(buffer, r);
        }
        close(fd);
        return content;
    }

    std::optional<std::string> metadata::get(const std::string& key) const
    {
        auto found = cache.find(key);
        if (found != cache.end()) return found->second;
        //else
        // A key genpack was not given when the image was built is simply not there, and an
        // image that is not a genpack one has no /.genpack at all.  Those keys only describe
        // the image and every caller can do without them, so one that cannot be reads the
        // same way here; get_lines() reports it instead.
        std::string problem;
        auto content = read_key(key, problem);
        std::optional<std::string> value;
        if (content) {
            auto end = content->find_last_not_of(" \t\r\n");
            if (end != std::string::npos) value = content->substr(0, end + 1);
        }
        cache[key] = value;
        return value;
    }

    std::vector<std::string> metadata::get_lines(const std::string& key) const
    {
        // Only a key the image does not have reads as no entries.  One that is there but
        // cannot be read is reported: quietly exporting nothing, and starting the VM
        // anyway, is worse than refusing to start it.
        std::string problem;
        auto content = read_key(key, problem);
        if (!content) {
            if (!problem.empty()) throw std::runtime_error(problem);
            return {};
        }

        std::vector<std::string> lines;
        std::istringstream stream(*content);
        std::string line;
        while (std::getline(stream, line)) {
            auto start = line.find_first_not_of(" \t\r");
            if (start == std::string::npos) continue; // blank
            auto end = line.find_last_not_of(" \t\r");
            line = line.substr(start, end - start + 1);
            if (line[0] == '#') continue;
            lines.push_back(line);
        }
        return lines;
    }

    // The key an image declares its exported ports in, and the option that does the same
    // from the command line: both are named in messages so that a reader can tell which
    // one an export came from.
    constexpr const char* vsock_exports_key = "/.genpack/vsock-exports";

    vsock_export parse_vsock_export(const std::string& what, const std::string& text)
    {
        auto invalid = [&](const std::string& reason) {
            return std::runtime_error("Invalid " + what + ": " + text + " (" + reason + ", expected PORT[:NAME])");
        };

        auto pos = text.find(':');
        auto port_str = pos == std::string::npos? text : text.substr(0, pos);
        auto name = pos == std::string::npos? port_str : text.substr(pos + 1);

        uint32_t port = 0;
        auto [ptr, ec] = std::from_chars(port_str.data(), port_str.data() + port_str.size(), port);
        if (ec != std::errc{} || ptr != port_str.data() + port_str.size() || port == 0 || port == 0xFFFFFFFF/*VMADDR_PORT_ANY*/) {
            throw invalid("port must be 1-4294967294");
        }
        if (name.empty() || name.size() > 64 || name.find_first_not_of('.') == std::string::npos
            || name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-") != std::string::npos) {
            throw invalid("NAME must be 1-64 characters of [A-Za-z0-9._-]");
        }
        return {port, name, what + " " + text};
    }

    std::vector<vsock_export> declared_vsock_exports(const metadata& image)
    {
        std::vector<std::string> lines;
        try {
            lines = image.get_lines("vsock-exports");
        } catch (const std::runtime_error& e) {
            // The path get_lines names lives on a mount that is on its way out, so say
            // which file of the image it was as well.
            throw std::runtime_error(std::string("Failed to read ") + vsock_exports_key
                + " of the system image: " + e.what());
        }

        std::vector<vsock_export> exports;
        for (const auto& line : lines) {
            exports.push_back(parse_vsock_export(vsock_exports_key, line));
        }
        return exports;
    }

    void check_vsock_exports(const std::vector<vsock_export>& exports)
    {
        // What was asked for from the command line has to name each name and each port
        // once: one name twice would collide on the socket's file name, one port twice
        // would relay the same guest port through two sockets.  The image's own
        // declarations are checked by merge_vsock_exports() instead, because there the
        // command line may cover for a duplicate; these are checked before any image is
        // read, so every boot path sees them.
        for (size_t i = 0; i < exports.size(); i++) {
            for (size_t j = i + 1; j < exports.size(); j++) {
                if (exports[i].name == exports[j].name)
                    throw std::runtime_error("Duplicate --export-vsock name: " + exports[i].name);
                if (exports[i].port == exports[j].port)
                    throw std::runtime_error("Duplicate --export-vsock port: " + std::to_string(exports[i].port)
                        + ", exported as both " + exports[i].name + " and " + exports[j].name);
            }
        }
    }

    std::vector<vsock_export> merge_vsock_exports(const std::vector<vsock_export>& requested,
        const std::vector<vsock_export>& declared, std::vector<std::string>& notices)
    {
        // The same export can be listed in the file more than once.  That names one
        // export, not two, and would say nothing twice, so the repeats go before
        // anything is compared.
        std::vector<vsock_export> unique;
        for (const auto& e : declared) {
            if (std::find_if(unique.begin(), unique.end(), [&](const vsock_export& m) {
                    return m.port == e.port && m.name == e.name;}) == unique.end())
                unique.push_back(e);
        }

        std::vector<vsock_export> merged = requested;

        for (const auto& e : unique) {
            auto port = std::find_if(merged.begin(), merged.end(),
                [&](const vsock_export& m) {return m.port == e.port;});
            if (port != merged.end()) {
                // The command line wins for a port it mentions, whatever name either
                // side gave it.  Whether an entry came from there is decided by where it
                // sits: the command line's are the first ones, in the order given.
                bool asked_for = port - merged.begin() < (ptrdiff_t)requested.size();
                if (!asked_for)
                    throw std::runtime_error(std::string(vsock_exports_key) + " exports port " + std::to_string(e.port)
                        + " twice, as " + port->name + " and as " + e.name);
                // Only worth saying when the command line renamed the export: the image
                // asking for what was asked for is the image agreeing with itself.
                if (port->name != e.name)
                    notices.push_back(std::string(vsock_exports_key) + " asks for " + std::to_string(e.port) + ":"
                        + e.name + ", overridden by " + port->source);
                continue;
            }
            auto name = std::find_if(merged.begin(), merged.end(),
                [&](const vsock_export& m) {return m.name == e.name;});
            if (name != merged.end()) {
                throw std::runtime_error(std::string(vsock_exports_key) + " exports port " + std::to_string(e.port)
                    + " as " + e.name + ", the name port " + std::to_string(name->port) + " is exported as ("
                    + name->source + ")");
            }
            merged.push_back(e);
        }

        return merged;
    }

    boot_files find_boot_files(const std::filesystem::path& ro_root, const std::filesystem::path& unpack_dir)
    {
        auto [kernel, initramfs] = find_kernel_and_initramfs(ro_root);

        // QEMU cannot boot a gzipped kernel, and an EFI zboot image is a PE stub
        // wrapped around one, so both are unpacked into unpack_dir: an ordinary file
        // in the VM's run directory, which goes away with it.
        uint8_t magic[2] = {};
        read_at(kernel, 0, magic, sizeof(magic));
        if (magic[0] == 0x1f && magic[1] == 0x8b) {
            auto unpacked = unpack_dir / (kernel.filename().string() + ".unpacked");
            unpack_gzip(kernel, unpacked, 0, false);
            kernel = unpacked;
        } else if (magic[0] == 'M' && magic[1] == 'Z') {
            // the zimg header is at offset 4 and the compression type it declares is
            // at offset 24
            uint8_t header[26] = {};
            read_at(kernel, 2, header, sizeof(header));
            if (std::memcmp(header, "\0\0zimg", 5) == 0 && std::memcmp(header + 22, "gzip", 4) == 0) {
                // the gzip stream follows the stub; look for its header
                std::vector<uint8_t> buffer(65536);
                auto size = read_at(kernel, 28, buffer.data(), buffer.size());
                std::string_view gzip_header("\x1f\x8b\x08\x00\x00\x00\x00\x00", 8);
                auto offset = std::string_view(reinterpret_cast<char*>(buffer.data()), size).find(gzip_header);
                if (offset == std::string_view::npos) throw std::runtime_error("No gzip stream found in " + kernel.string());
                //else
                auto unpacked = unpack_dir / (kernel.filename().string() + ".unpacked");
                unpack_gzip(kernel, unpacked, 28 + static_cast<off_t>(offset), true);
                kernel = unpacked;
            }
        }

        // the CPU architecture the kernel was built for, from its magic number
        uint8_t buf[518] = {}; // far enough to reach the x86 setup header's magic
        auto size = read_at(kernel, 0, buf, sizeof(buf));
        std::optional<std::string> arch;
        if (size >= (ssize_t)sizeof(buf) && buf[514] == 'H' && buf[515] == 'd' && buf[516] == 'r' && buf[517] == 'S')
            arch = "x86_64";
        else if (size >= 0x3c && buf[0x38] == 0x41 && buf[0x39] == 0x52 && buf[0x3a] == 0x4d && buf[0x3b] == 0x64)
            arch = "aarch64";
        else if (size >= 0x35 && buf[0x30] == 'R' && buf[0x31] == 'I' && buf[0x32] == 'S' && buf[0x33] == 'C' && buf[0x34] == 'V')
            arch = "riscv64";

        return {kernel, initramfs, arch};
    }
} // namespace system_image
