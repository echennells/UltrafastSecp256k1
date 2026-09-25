// =============================================================================
// UltrafastSecp256k1 OpenCL - Program Build With Binary Cache
// =============================================================================
#pragma once

#include <cstddef>

#ifdef __APPLE__
    #include <OpenCL/cl.h>
#else
    #include <CL/cl.h>
#endif

namespace secp256k1 {
namespace opencl {

// Create and build a program for one device from source. Without a cache
// every process start recompiles each program, which takes minutes for the
// larger ones on some drivers (AMD ROCm: ~140 s for secp256k1_extended.cl).
// A binary built earlier is reused when the sources, the files in the -I
// directories of the options, the options, the device and the driver all
// match; the full key is stored in the cache file and compared on load.
//
// The cache is in $UFSECP_OPENCL_CACHE_DIR, else the user cache directory
// (ufsecp/opencl), and UFSECP_OPENCL_CACHE=0 disables it. A cached binary is
// trusted as the kernel sources read from disk are. Cache failures are
// silent: the program is then compiled from source.
//
// Sets *program, also when the build fails so the caller can read the build
// log, and returns the build result. *program is null if creation failed.
cl_int build_program(cl_context context, cl_device_id device, cl_uint count,
    const char** sources, const std::size_t* lengths, const char* options,
    cl_program* program);

} // namespace opencl
} // namespace secp256k1
