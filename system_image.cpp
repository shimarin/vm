#include "system_image.h"

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

    std::optional<std::string> metadata::get(const std::string& key) const
    {
        auto found = cache.find(key);
        if (found != cache.end()) return found->second;
        //else
        // A key genpack was not given when the image was built is simply not there,
        // and an image that is not a genpack one has no /.genpack at all.
        std::optional<std::string> value;
        std::ifstream file(dir / key);
        if (!file.fail()) {
            auto content = std::string{std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
            auto end = content.find_last_not_of(" \t\r\n");
            if (end != std::string::npos) value = content.substr(0, end + 1);
        }
        cache[key] = value;
        return value;
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
