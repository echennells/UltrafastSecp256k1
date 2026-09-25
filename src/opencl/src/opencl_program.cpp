// =============================================================================
// UltrafastSecp256k1 OpenCL - Program Build With Binary Cache
// =============================================================================

#include "opencl_program.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <random>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

namespace secp256k1 {
namespace opencl {
namespace {

// Also the first key field, so a format change misses every older entry.
constexpr char cache_magic[8] = { 'U', 'F', 'C', 'L', 'B', 'I', 'N', '1' };

void append(std::string& key, const void* data, std::size_t size) {
    const std::uint64_t length = size;
    key.append(reinterpret_cast<const char*>(&length), sizeof(length));
    key.append(static_cast<const char*>(data), size);
}

void append(std::string& key, const std::string& value) {
    append(key, value.data(), value.size());
}

std::string device_string(cl_device_id device, cl_device_info param) {
    std::size_t size = 0;
    if (clGetDeviceInfo(device, param, 0, nullptr, &size) != CL_SUCCESS || size == 0)
        return {};
    std::string value(size, '\0');
    if (clGetDeviceInfo(device, param, size, value.data(), nullptr) != CL_SUCCESS)
        return {};
    value.resize(std::strlen(value.c_str()));
    return value;
}

std::string platform_string(cl_device_id device, cl_platform_info param) {
    cl_platform_id platform = nullptr;
    if (clGetDeviceInfo(device, CL_DEVICE_PLATFORM, sizeof(platform), &platform, nullptr) != CL_SUCCESS)
        return {};
    std::size_t size = 0;
    if (clGetPlatformInfo(platform, param, 0, nullptr, &size) != CL_SUCCESS || size == 0)
        return {};
    std::string value(size, '\0');
    if (clGetPlatformInfo(platform, param, size, value.data(), nullptr) != CL_SUCCESS)
        return {};
    value.resize(std::strlen(value.c_str()));
    return value;
}

bool read_file(const std::filesystem::path& path, std::string& out) {
    std::ifstream file(path, std::ios::binary);
    if (!file)
        return false;
    out.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
    return !file.bad();
}

// Files in the -I directories of the options are compiled in by #include.
void append_includes(std::string& key, const std::string& options) {
    std::istringstream tokens(options);
    std::string token;
    while (tokens >> token) {
        std::string directory;
        if (token == "-I") {
            if (!(tokens >> directory))
                break;
        } else if (token.rfind("-I", 0) == 0) {
            directory = token.substr(2);
        } else {
            continue;
        }

        std::vector<std::filesystem::path> files;
        std::error_code ec;
        for (std::filesystem::directory_iterator it(directory, ec), end; !ec && it != end; it.increment(ec)) {
            const auto extension = it->path().extension();
            if (it->is_regular_file(ec) && (extension == ".cl" || extension == ".h"))
                files.push_back(it->path());
        }

        std::sort(files.begin(), files.end());
        for (const auto& path : files) {
            std::string contents;
            read_file(path, contents);
            append(key, path.filename().string());
            append(key, contents);
        }
    }
}

std::filesystem::path cache_directory() {
    const char* enabled = std::getenv("UFSECP_OPENCL_CACHE");
    if (enabled && std::strcmp(enabled, "0") == 0)
        return {};
    const char* directory = std::getenv("UFSECP_OPENCL_CACHE_DIR");
    if (directory && directory[0])
        return directory;
#if defined(_WIN32)
    const char* local = std::getenv("LOCALAPPDATA");
    if (local && local[0])
        return std::filesystem::path(local) / "ufsecp" / "opencl";
#else
    const char* xdg = std::getenv("XDG_CACHE_HOME");
    if (xdg && xdg[0])
        return std::filesystem::path(xdg) / "ufsecp" / "opencl";
    const char* home = std::getenv("HOME");
    if (home && home[0])
        return std::filesystem::path(home) / ".cache" / "ufsecp" / "opencl";
#endif
    return {};
}

// FNV-1a only names the file; the full key stored in it is compared on load.
std::string file_name(const std::string& key) {
    std::uint64_t hash = 0xcbf29ce484222325ull;
    for (const unsigned char byte : key) {
        hash ^= byte;
        hash *= 0x100000001b3ull;
    }
    char name[24];
    std::snprintf(name, sizeof(name), "%016llx.bin", static_cast<unsigned long long>(hash));
    return name;
}

// File layout: magic | key size (u64) | key | binary.
bool read_binary(const std::filesystem::path& path, const std::string& key, std::string& binary) {
    std::string contents;
    if (!read_file(path, contents))
        return false;
    std::uint64_t key_size = 0;
    const std::size_t header = sizeof(cache_magic) + sizeof(key_size);
    if (contents.size() <= header + key.size() ||
        std::memcmp(contents.data(), cache_magic, sizeof(cache_magic)) != 0)
        return false;
    std::memcpy(&key_size, contents.data() + sizeof(cache_magic), sizeof(key_size));
    if (key_size != key.size() || contents.compare(header, key.size(), key) != 0)
        return false;
    binary = contents.substr(header + key.size());
    return true;
}

void write_binary(const std::filesystem::path& path, const std::string& key,
    cl_program program, cl_device_id device) {
    cl_uint count = 0;
    if (clGetProgramInfo(program, CL_PROGRAM_NUM_DEVICES, sizeof(count), &count, nullptr) != CL_SUCCESS ||
        count == 0)
        return;
    std::vector<cl_device_id> devices(count);
    std::vector<std::size_t> sizes(count);
    if (clGetProgramInfo(program, CL_PROGRAM_DEVICES, count * sizeof(cl_device_id), devices.data(), nullptr) != CL_SUCCESS ||
        clGetProgramInfo(program, CL_PROGRAM_BINARY_SIZES, count * sizeof(std::size_t), sizes.data(), nullptr) != CL_SUCCESS)
        return;
    const auto index = static_cast<std::size_t>(std::find(devices.begin(), devices.end(), device) - devices.begin());
    if (index == devices.size() || sizes[index] == 0)
        return;

    // A null entry skips the binary of that device.
    std::string binary(sizes[index], '\0');
    std::vector<unsigned char*> binaries(count, nullptr);
    binaries[index] = reinterpret_cast<unsigned char*>(binary.data());
    if (clGetProgramInfo(program, CL_PROGRAM_BINARIES, count * sizeof(unsigned char*), binaries.data(), nullptr) != CL_SUCCESS)
        return;

    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec)
        return;

    // Written aside and renamed, so a reader never sees a partial file.
    std::random_device random;
    auto temporary = path;
    temporary += "." + std::to_string(random()) + ".tmp";
    {
        std::ofstream file(temporary, std::ios::binary | std::ios::trunc);
        const std::uint64_t key_size = key.size();
        file.write(cache_magic, sizeof(cache_magic));
        file.write(reinterpret_cast<const char*>(&key_size), sizeof(key_size));
        file.write(key.data(), static_cast<std::streamsize>(key.size()));
        file.write(binary.data(), static_cast<std::streamsize>(binary.size()));
        if (!file) {
            file.close();
            std::filesystem::remove(temporary, ec);
            return;
        }
    }
    std::filesystem::rename(temporary, path, ec);
    if (ec)
        std::filesystem::remove(temporary, ec);
}

} // namespace

cl_int build_program(cl_context context, cl_device_id device, cl_uint count,
    const char** sources, const std::size_t* lengths, const char* options,
    cl_program* program) {
    *program = nullptr;
    const std::string build_options = options ? options : "";

    std::string key;
    std::filesystem::path path;
    const auto directory = cache_directory();
    if (!directory.empty()) {
        append(key, cache_magic, sizeof(cache_magic));
        append(key, platform_string(device, CL_PLATFORM_NAME));
        append(key, platform_string(device, CL_PLATFORM_VERSION));
        append(key, device_string(device, CL_DEVICE_NAME));
        append(key, device_string(device, CL_DEVICE_VENDOR));
        append(key, device_string(device, CL_DEVICE_VERSION));
        append(key, device_string(device, CL_DRIVER_VERSION));
        append(key, build_options);
        for (cl_uint i = 0; i < count; ++i) {
            const std::size_t length = (lengths && lengths[i]) ? lengths[i] : std::strlen(sources[i]);
            append(key, sources[i], length);
        }
        append_includes(key, build_options);
        path = directory / file_name(key);

        std::string binary;
        if (read_binary(path, key, binary)) {
            const auto* data = reinterpret_cast<const unsigned char*>(binary.data());
            const std::size_t size = binary.size();
            cl_int status = CL_SUCCESS;
            cl_int err = CL_SUCCESS;
            cl_program cached = clCreateProgramWithBinary(context, 1, &device, &size, &data, &status, &err);
            if (cached && err == CL_SUCCESS && status == CL_SUCCESS &&
                clBuildProgram(cached, 1, &device, build_options.c_str(), nullptr, nullptr) == CL_SUCCESS) {
                *program = cached;
                return CL_SUCCESS;
            }

            // Rejected by the driver, so compile from source and replace it.
            if (cached)
                clReleaseProgram(cached);
        }
    }

    cl_int err = CL_SUCCESS;
    cl_program built = clCreateProgramWithSource(context, count, sources, lengths, &err);
    if (err != CL_SUCCESS || !built) {
        if (built)
            clReleaseProgram(built);
        return err != CL_SUCCESS ? err : CL_OUT_OF_HOST_MEMORY;
    }

    *program = built;
    err = clBuildProgram(built, 1, &device, build_options.c_str(), nullptr, nullptr);
    if (err == CL_SUCCESS && !path.empty())
        write_binary(path, key, built, device);
    return err;
}

} // namespace opencl
} // namespace secp256k1
