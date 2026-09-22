// ============================================================================
// test_regression_fixed_base_cache_lifecycle.cpp
// ============================================================================
// Regression: the fixed-base precompute table must not litter the caller's
// working directory, and a configured cache directory must be honoured for
// WRITING and not only for reading.
//
// Reported by Eric Voskuil (evoskuil):
//
//   "This file keeps getting left behind, such as in my test case executions:
//    cache_w18.bin. [...] My first preference is that it's not written at all.
//    Second preference is that it's manageable (we can control the path/name),
//    defaulting to temp. Third preference is that it's treated as a temp file
//    (temp directory, cleaned up). Last preference is that a math lib leaves
//    files behind in our working directory."
//
// We shipped the last one. `FixedBaseConfig::use_cache` defaulted to true and
// `cache_dir` defaulted to empty, and `get_default_cache_path()` consulted
// cache_dir only when a file ALREADY existed there:
//
//     if (!g_config.cache_dir.empty()) {
//         std::string cache_path = g_config.cache_dir + "/" + filename;
//         if (::stat(cache_path.c_str(), &st) == 0)   // only if it exists
//             return cache_path;
//     }
//     return filename;                                 // otherwise the CWD
//
// So a caller who had called set_cache_directory() still wrote its first cache
// into the working directory, and a caller who had configured nothing got a
// 255 MB cache_w18.bin (window_bits=18 by default) dropped wherever it ran.
//
// The table is now built ONCE and reused: the default is to save it to the
// per-user cache directory the platform reserves for this
// ($XDG_CACHE_HOME/secp256k1 or ~/.cache/secp256k1, ~/Library/Caches/secp256k1,
// %LOCALAPPDATA%\\secp256k1) and load it thereafter. The location is what was
// wrong before, not the caching.
//
// What this pins:
//   FBC-1  the default matches how the library was built, and with the cache
//          OFF nothing is written anywhere
//   FBC-2  with the cache enabled and a directory named, the file is created
//          THERE on the first run -- the case the old resolver got wrong
//   FBC-3  with the cache enabled and NO directory named, nothing lands in the
//          CWD (it goes to the per-user cache directory instead)
//   FBC-4  a caller-named cache file survives a reconfigure -- being loadable
//          by the next process is the whole point, so it is not ours to delete
//
// Build-flag coupling: SECP256K1_FIXED_BASE_DISK_CACHE selects the default for
// use_cache. Both modes are exercised here regardless of how the library was
// built, by setting use_cache explicitly through FixedBaseConfig.
// ============================================================================

#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>
#include <filesystem>
#include <system_error>
#if !defined(_WIN32)
#include <sys/stat.h>   // mkdir, lstat, S_ISDIR, S_IWGRP, S_IWOTH  (FBC-5)
#include <unistd.h>     // geteuid                                  (FBC-5)
#include <cerrno>       // errno / EEXIST                           (FBC-5)
#include <sys/wait.h>   // fork/waitpid/WIFEXITED                   (FBC-5e)
#include <cstdlib>      // setenv, unsetenv, getenv                 (FBC-5e)
#endif

#include "secp256k1/precompute.hpp"
#include "secp256k1/point.hpp"
#include "secp256k1/scalar.hpp"

#include "audit_check.hpp"

static int g_pass = 0, g_fail = 0;

namespace {

namespace fs = std::filesystem;
using secp256k1::fast::FixedBaseConfig;

// Small window: the point is the file's location and lifetime, not its size.
// window_bits=18 would make every case in this module allocate 255 MB.
constexpr unsigned kWindow = 4;

std::vector<fs::path> cache_files_in(const fs::path& dir) {
    std::vector<fs::path> found;
    std::error_code ec;
    for (auto const& e : fs::directory_iterator(dir, ec)) {
        auto const name = e.path().filename().string();
        if (name.rfind("cache_w", 0) == 0) found.push_back(e.path());
    }
    return found;
}

// Force the table to be built (and, when caching is on, written).
void build_table(const FixedBaseConfig& cfg) {
    secp256k1::fast::configure_fixed_base(cfg);
    secp256k1::fast::ensure_fixed_base_ready();
    // Touch it so a lazy implementation cannot skip the build entirely.
    (void)secp256k1::fast::scalar_mul_generator(
        secp256k1::fast::Scalar::from_uint64(12345));
}

#if !defined(_WIN32)
// FBC-5e runs the library's OWN temp-fallback code, in a child process.
//
// The checks in FBC-5a..d mirror secure_temp_cache_dir()'s logic rather than
// calling it, because it is file-local to precompute.cpp. That validates the
// contract but executes none of the shipped code -- codecov reported the patch
// at 0%, which was a fair verdict on a test that only restates what the code is
// supposed to do.
//
// Reaching the real path in-process is not possible: compute_default_cache_dir()
// is memoised in a function-local static, so by the time FBC-1..4 have each
// built a table the answer is already fixed, and clearing HOME afterwards
// changes nothing. A child process with a scrubbed environment starts that
// static fresh.
//
// STANDALONE_TEST only. Inside unified_audit_runner argv[0] is the runner, and
// re-executing it would run the entire audit suite recursively.
constexpr const char* kChildEnvVar = "UFSECP_FBC_TEMP_FALLBACK_DIR";
const char* g_self_path = nullptr;   // argv[0], set by main()

// The child half: HOME/XDG_CACHE_HOME are already unset and TMPDIR points at a
// scratch directory, so the default cache directory must resolve through
// secure_temp_cache_dir(). Build a table with the cache on and let it land.
//
// The file has to be checked HERE, before this process exits. A temp-fallback
// cache is deliberately session-scoped: cache_path_is_ours() is true for it, so
// register_temp_cache_for_cleanup() deletes it on exit. The parent would
// therefore find an empty directory and conclude the library had failed, when
// in fact it had done exactly what it documents.
//
// Exit codes: 0 = the cache landed in <temp>/secp256k1-<uid>/, 3 = it did not.
int run_temp_fallback_child() {
    FixedBaseConfig cfg{};
    cfg.window_bits = kWindow;
    cfg.use_cache   = true;
    cfg.cache_dir   = "";          // no directory named -> library decides
    build_table(cfg);

    const char* const tmpdir = std::getenv("TMPDIR");
    if (tmpdir == nullptr || *tmpdir == '\0') return 3;
    fs::path const priv = fs::path(tmpdir) /
        ("secp256k1-" + std::to_string(static_cast<unsigned long>(::geteuid())));
    return cache_files_in(priv).empty() ? 3 : 0;
}
#endif

struct CwdGuard {
    fs::path saved;
    bool ok = false;
    explicit CwdGuard(const fs::path& to) {
        std::error_code ec;
        saved = fs::current_path(ec);
        ok = !ec;
        if (ok) fs::current_path(to, ec);
    }
    ~CwdGuard() {
        if (!ok) return;
        std::error_code ec;
        fs::current_path(saved, ec);
    }
};

} // namespace

int test_regression_fixed_base_cache_lifecycle_run() {
    g_pass = 0; g_fail = 0;
    std::printf("======================================================================\n");
    std::printf("  Regression: fixed-base cache does not litter the working directory\n");
    std::printf("======================================================================\n\n");

    std::error_code ec;
    fs::path const base = fs::temp_directory_path(ec) / "ufsecp_fbc_lifecycle";
    fs::remove_all(base, ec);
    fs::create_directories(base, ec);
    CHECK(!ec, "FBC-0: scratch directory created");
    if (ec) { std::printf("\n[regression_fixed_base_cache_lifecycle] %d/%d checks passed\n",
                          g_pass, g_pass + g_fail); return 1; }

    // ── FBC-1: the default writes nothing ────────────────────────────────────
    {
        fs::path const cwd = base / "default_mode";
        fs::create_directories(cwd, ec);
        CwdGuard guard(cwd);

        FixedBaseConfig cfg;              // defaults, whatever the build chose
        cfg.window_bits = kWindow;

        // The default has to agree with the build flag in BOTH directions. A
        // header that says one thing while the library was compiled expecting
        // the other is an ODR-shaped mismatch, not a preference.
#if defined(SECP256K1_FIXED_BASE_DISK_CACHE) && !SECP256K1_FIXED_BASE_DISK_CACHE
        CHECK(!cfg.use_cache,
              "FBC-1: built with -DSECP256K1_FIXED_BASE_DISK_CACHE=OFF, so "
              "FixedBaseConfig defaults to use_cache=false and the table is "
              "rebuilt in every process with nothing written");
#else
        CHECK(cfg.use_cache,
              "FBC-1: FixedBaseConfig defaults to use_cache=true -- the table is "
              "built once, saved to the per-user cache directory, and loaded by "
              "every later process (never the working directory)");
#endif

        cfg.use_cache = false;            // pin the mode under test either way
        build_table(cfg);
        auto const left = cache_files_in(cwd);
        CHECK(left.empty(),
              "FBC-1: with the cache off, no cache_w* file is created in the "
              "working directory");
        for (auto const& f : left) std::printf("      unexpected: %s\n", f.string().c_str());
    }

    // ── FBC-2: a named directory is honoured on the FIRST run ────────────────
    {
        fs::path const cwd     = base / "named_cwd";
        fs::path const cachedir = base / "named_cache";
        fs::create_directories(cwd, ec);
        fs::create_directories(cachedir, ec);
        CwdGuard guard(cwd);

        FixedBaseConfig cfg;
        cfg.window_bits = kWindow;
        cfg.use_cache = true;
        cfg.cache_dir = cachedir.string();
        build_table(cfg);

        auto const in_cache = cache_files_in(cachedir);
        auto const in_cwd   = cache_files_in(cwd);
        CHECK(!in_cache.empty(),
              "FBC-2: the cache file is created in the configured cache_dir on the "
              "first run -- the old resolver only READ from cache_dir and wrote to "
              "the CWD until someone seeded the file by hand");
        CHECK(in_cwd.empty(),
              "FBC-2: nothing is written to the working directory when a cache_dir "
              "is configured");
        for (auto const& f : in_cwd) std::printf("      unexpected: %s\n", f.string().c_str());

        // ── FBC-4: the caller's file is the caller's ─────────────────────────
        // Persistence across processes is the only reason to name a directory,
        // so the library must not delete what it finds there.
        secp256k1::fast::configure_fixed_base(FixedBaseConfig{});  // drop the context
        bool still_there = !cache_files_in(cachedir).empty();
        CHECK(still_there,
              "FBC-4: a cache file in a caller-named directory survives "
              "reconfiguration -- the next process loading it instead of "
              "rebuilding is the whole point, so it is not ours to delete");
    }

    // ── FBC-3: cache on, no directory named -> not the CWD ───────────────────
    {
        fs::path const cwd = base / "unnamed_cwd";
        fs::create_directories(cwd, ec);
        CwdGuard guard(cwd);

        FixedBaseConfig cfg;
        cfg.window_bits = kWindow;
        cfg.use_cache = true;
        cfg.cache_dir = "";               // no directory named
        build_table(cfg);

        auto const in_cwd = cache_files_in(cwd);
        CHECK(in_cwd.empty(),
              "FBC-3: with the cache on and no cache_dir configured, the file goes "
              "to the per-user cache directory, never to the working directory");
        for (auto const& f : in_cwd) std::printf("      unexpected: %s\n", f.string().c_str());
    }

    // ── FBC-5: the temp fallback is a private directory, or it is refused ────
    //
    // SonarCloud cpp:S5443, fixed 2026-09-21. When no per-user cache directory
    // can be determined -- no HOME, no XDG_CACHE_HOME, no LOCALAPPDATA, which is
    // what a daemon with a scrubbed environment or a bare container looks like --
    // the cache used to fall back to the temp directory ITSELF. That directory is
    // world-writable and the filename is predictable (cache_w18.bin), so any
    // local user could plant a file there and have it loaded: the loader's
    // validate_precompute_context() checks window counts, digit counts and table
    // SHAPE, never that the points are genuine multiples of G. A poisoned table
    // of the right shape is accepted -- and it is the FIXED-BASE table, so it
    // decides the result of every k*G, i.e. every public key derived through it.
    //
    // This pins the three properties of the replacement, secure_temp_cache_dir():
    // the directory is per-user, it is private (0700, no group/other write), and
    // a hostile pre-existing entry at that path is REFUSED rather than used.
    // The checks mirror that function's POSIX body rather than calling it --
    // it is file-local to precompute.cpp -- so if the implementation ever drops
    // one of them this test still describes what the contract has to be.
#if !defined(_WIN32)
    {
        fs::path const tmpbase = base / "tempfallback";
        fs::create_directories(tmpbase, ec);

        auto secure_dir_for = [](const std::string& b) -> std::string {
            if (b.empty()) return {};
            std::string const dir = b + "/secp256k1-" +
                                    std::to_string(static_cast<unsigned long>(::geteuid()));
            if (::mkdir(dir.c_str(), 0700) != 0 && errno != EEXIST) return {};
            struct stat st{};
            if (::lstat(dir.c_str(), &st) != 0)           return {};
            if (!S_ISDIR(st.st_mode))                     return {};
            if (st.st_uid != ::geteuid())                 return {};
            if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0)  return {};
            return dir;
        };

        // (a) the normal case yields a per-user directory, created 0700
        std::string const good = secure_dir_for(tmpbase.string());
        CHECK(!good.empty(),
              "FBC-5a: a private per-user directory is established under the temp dir");
        if (!good.empty()) {
            struct stat st{};
            bool const stat_ok = ::lstat(good.c_str(), &st) == 0;
            CHECK(stat_ok && (st.st_mode & (S_IWGRP | S_IWOTH)) == 0,
                  "FBC-5b: that directory is not group- or world-writable");
            CHECK(good.find("secp256k1-") != std::string::npos,
                  "FBC-5c: the directory is namespaced per user, not the bare temp dir");
        }

        // (b) a symlink planted at the path is refused, not followed.
        //     This is the attack the old code was open to, so it is the check
        //     that must fail if the lstat/S_ISDIR pair is ever dropped.
        fs::path const hostile_base = base / "hostile";
        fs::create_directories(hostile_base, ec);
        std::string const planted = hostile_base.string() + "/secp256k1-" +
                                    std::to_string(static_cast<unsigned long>(::geteuid()));
        fs::path const elsewhere = base / "attacker_target";
        fs::create_directories(elsewhere, ec);
        std::error_code link_ec;
        fs::create_directory_symlink(elsewhere, planted, link_ec);
        if (!link_ec) {
            CHECK(secure_dir_for(hostile_base.string()).empty(),
                  "FBC-5d: a symlink planted at the cache directory path is REFUSED "
                  "(lstat + S_ISDIR), never followed to the attacker's target");
        } else {
            std::printf("      note: symlink not creatable here, FBC-5d not exercised\n");
        }
    }

    // ── FBC-5e: run the library's own temp fallback, in a child process ──────
    //
    // FBC-5a..d above mirror secure_temp_cache_dir()'s logic. This one EXECUTES
    // it: a child with HOME and XDG_CACHE_HOME removed and TMPDIR pointing at a
    // scratch directory has no per-user cache directory, so the library must
    // resolve through the temp fallback -- and the file has to land in
    // <scratch>/secp256k1-<uid>/, not in <scratch> itself.
    //
    // A child is required, not a convenience: compute_default_cache_dir() is
    // memoised in a function-local static, so in this process the answer was
    // already fixed by FBC-1.
    if (g_self_path != nullptr) {
        fs::path const scratch = base / "childfallback";
        fs::create_directories(scratch, ec);

        pid_t const pid = ::fork();
        if (pid == 0) {
            // Child: scrub the environment, then re-exec ourselves. execv gives
            // a fresh process image, so the memoised static starts unset.
            ::setenv(kChildEnvVar, scratch.string().c_str(), 1);
            ::setenv("TMPDIR", scratch.string().c_str(), 1);
            ::unsetenv("HOME");
            ::unsetenv("XDG_CACHE_HOME");
            ::unsetenv("TMP");
            ::unsetenv("TEMP");
            char* argv0 = const_cast<char*>(g_self_path);
            char* const argv[] = {argv0, nullptr};
            ::execv(g_self_path, argv);
            ::_exit(127);              // execv only returns on failure
        }

        if (pid < 0) {
            std::printf("      note: fork() unavailable, FBC-5e not exercised\n");
        } else {
            int status = 0;
            ::waitpid(pid, &status, 0);
            // exit 0 means the child SAW the cache file inside
            // <temp>/secp256k1-<uid>/ before it exited. Checking from here would
            // be wrong: a temp-fallback cache is session-scoped, so
            // register_temp_cache_for_cleanup() has already deleted it by the
            // time waitpid returns -- correct behaviour that would read as
            // failure from the parent.
            int const code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            CHECK(code == 0,
                  "FBC-5e: with no HOME and no XDG_CACHE_HOME, the library resolved "
                  "through secure_temp_cache_dir() and wrote the cache into "
                  "<temp>/secp256k1-<uid>/ (child exit 0; 3 = wrong location)");
            if (code != 0) std::printf("      child exit code: %d\n", code);

            std::string const priv = scratch.string() + "/secp256k1-" +
                std::to_string(static_cast<unsigned long>(::geteuid()));

            auto const stray = cache_files_in(scratch);
            CHECK(stray.empty(),
                  "FBC-5e: nothing is written into the bare temp directory itself");
            for (auto const& f : stray) std::printf("      unexpected: %s\n", f.string().c_str());

            std::error_code pec;
            CHECK(fs::is_directory(priv, pec),
                  "FBC-5e: the private per-user directory the library created "
                  "survives the run (the cache file inside it does not, by design)");

            struct stat pst{};
            if (::lstat(priv.c_str(), &pst) == 0) {
                CHECK((pst.st_mode & (S_IWGRP | S_IWOTH)) == 0,
                      "FBC-5e: the directory the library created is not group- or "
                      "world-writable");
            }
        }
    }
#endif

    // Leave the default mode active for whatever runs after this module.
    secp256k1::fast::configure_fixed_base(FixedBaseConfig{});
    fs::remove_all(base, ec);

    std::printf("\n[regression_fixed_base_cache_lifecycle] %d/%d checks passed\n",
                g_pass, g_pass + g_fail);
    return (g_fail > 0) ? 1 : 0;
}

#ifdef STANDALONE_TEST
int main(int argc, char** argv) {
#if !defined(_WIN32)
    // Re-executed by FBC-5e with a scrubbed environment: do only the child's
    // job. This must happen BEFORE anything else touches the fixed-base
    // machinery, because compute_default_cache_dir() memoises its answer.
    if (const char* scratch = std::getenv(kChildEnvVar)) {
        (void)scratch;
        return run_temp_fallback_child();
    }
    g_self_path = (argc > 0) ? argv[0] : nullptr;
#else
    (void)argc; (void)argv;
#endif
    return test_regression_fixed_base_cache_lifecycle_run();
}
#endif
