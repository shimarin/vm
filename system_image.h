#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <sys/types.h>

namespace system_image {
    // A read-only mount of a squashfs image, made with squashfuse(1) in the
    // host's mount namespace so that the contents of the image stay visible on
    // the host while the VM runs (the guest is given the image itself as its
    // disk; this mount is only used to read boot files out of the image).
    //
    // squashfuse is run in the foreground (-f) as a child of this process:
    //   - PR_SET_PDEATHSIG ties it to our lifetime, so the mount is released
    //     even if we are killed, and
    //   - ~ro_mount sends SIGTERM and waits for it, so the mount is released on
    //     a normal shutdown as well.
    // The mount itself is made with -o auto_unmount so that fusermount3(1) also
    // removes the mount entry on its own; check_auto_unmount() checks that the host
    // really behaves that way before vm relies on it.
    class ro_mount {
    public:
        ro_mount(const std::filesystem::path& image, const std::filesystem::path& mountpoint);
        ~ro_mount();

        ro_mount(const ro_mount&) = delete;
        ro_mount& operator=(const ro_mount&) = delete;
        ro_mount(ro_mount&& other) noexcept;
        ro_mount& operator=(ro_mount&& other) noexcept;

        const std::filesystem::path& get_mountpoint() const {return mountpoint;}

        // Removes a mount left at mountpoint by a VM that was killed without a
        // chance to unmount, the same way stale vsock sockets are removed when
        // a VM starts.  Throws if the mount cannot be removed.
        static void sweep_stale(const std::filesystem::path& mountpoint);

        // SIGKILLs the squashfuse process backing this mount and checks that the
        // mount entry goes away with it, which is what keeps a mount from outliving
        // a VM that was killed.  vm calls it on the scratch mount it has just read
        // from: what has to hold is the case where the mount was really in use, not
        // one that has only just appeared.  Returns false when the mount stayed
        // behind, meaning this host's fuse support does not honour auto_unmount; the
        // mount is taken down by asking fusermount before returning either way, and
        // ~ro_mount has nothing left to do.  Throws when the mount is still in the
        // mount table at that point, naming the command that removes it rather than
        // pretending the scratch directory is free.
        bool check_auto_unmount();

    private:
        // Stops squashfuse and takes the mount down.  ~ro_mount and move assignment
        // both go through this; a mount that cannot be unmounted is reported with
        // the command that would remove it, since there is nothing left to do here.
        void release() noexcept;

        pid_t pid = -1;
        std::filesystem::path mountpoint;
    };

    // A file under /.genpack/ of a genpack image.  genpack writes arch, profile,
    // artifact, variant, commit-id, timestamp.commit and packages there, and an
    // artifact may add files of its own, so a key that is not there simply reads
    // as std::nullopt and reading another one is a matter of naming it.
    class metadata {
    public:
        explicit metadata(std::filesystem::path ro_root);

        std::optional<std::string> get(const std::string& key) const;
        bool has(const std::string& key) const {return get(key).has_value();}

        std::optional<std::string> arch() const {return get("arch");}
        std::optional<std::string> profile() const {return get("profile");}
        std::optional<std::string> artifact() const {return get("artifact");}
        std::optional<std::string> variant() const {return get("variant");}
        std::optional<std::string> commit_id() const {return get("commit-id");}
        std::optional<std::string> timestamp_commit() const {return get("timestamp.commit");}

    private:
        std::filesystem::path dir;
        mutable std::map<std::string, std::optional<std::string>> cache;
    };

    struct boot_files {
        std::filesystem::path kernel;
        std::optional<std::filesystem::path> initramfs;
        std::optional<std::string> arch;
    };

    // Looks for the kernel and initramfs under <ro_root>/boot.  A kernel QEMU
    // cannot boot as-is (a gzipped kernel, or an EFI zboot image wrapping one)
    // is unpacked into unpack_dir and its new path returned instead.  arch is
    // read from the magic number of the kernel that is finally returned.
    boot_files find_boot_files(const std::filesystem::path& ro_root, const std::filesystem::path& unpack_dir);
} // namespace system_image
