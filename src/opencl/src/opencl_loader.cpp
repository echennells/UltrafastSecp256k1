// =============================================================================
// UltrafastSecp256k1 OpenCL - Runtime Loader
// =============================================================================
// Defines the OpenCL entry points this library uses and forwards each to the
// OpenCL runtime (ICD loader), which is loaded on first use instead of being
// linked. A consumer therefore starts on a host without an OpenCL runtime
// (no libOpenCL.so.1 / OpenCL.dll), where clGetPlatformIDs reports no
// platform and the backend is unavailable. Built when
// SECP256K1_OPENCL_RUNTIME_LOAD is ON (src/opencl/CMakeLists.txt).
// =============================================================================

#if defined(_WIN32)
    #ifndef NOMINMAX
        #define NOMINMAX
    #endif
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
#else
    #include <dlfcn.h>
#endif

#ifdef __APPLE__
    #include <OpenCL/cl.h>
#else
    #include <CL/cl.h>
#endif

#include <cstring>

#ifndef CL_PLATFORM_NOT_FOUND_KHR
    #define CL_PLATFORM_NOT_FOUND_KHR -1001
#endif

namespace {

void* runtime() noexcept {
    static void* const handle = []() noexcept -> void* {
#if defined(_WIN32)
        // System directory only, the ICD loader is installed there.
        return LoadLibraryExW(L"OpenCL.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
#elif defined(__APPLE__)
        return dlopen("/System/Library/Frameworks/OpenCL.framework/OpenCL", RTLD_NOW | RTLD_LOCAL);
#else
        void* library = dlopen("libOpenCL.so.1", RTLD_NOW | RTLD_LOCAL);
        return library ? library : dlopen("libOpenCL.so", RTLD_NOW | RTLD_LOCAL);
#endif
    }();
    return handle;
}

template <typename Function>
Function resolve(const char* name) noexcept {
    void* address = nullptr;
    if (void* const handle = runtime()) {
#if defined(_WIN32)
        const FARPROC procedure = GetProcAddress(static_cast<HMODULE>(handle), name);
        static_assert(sizeof(procedure) == sizeof(address), "pointer size");
        std::memcpy(&address, &procedure, sizeof(address));
#else
        address = dlsym(handle, name);
#endif
    }

    Function function = nullptr;
    static_assert(sizeof(function) == sizeof(address), "pointer size");
    std::memcpy(&function, &address, sizeof(function));
    return function;
}

} // namespace

// Each entry point resolves its runtime function once. Without a runtime it
// fails as a runtime would without a platform.
#define UFSECP_CL_FORWARD(result, name, parameters, arguments, failure)    \
    CL_API_ENTRY result CL_API_CALL name parameters {                      \
        static const auto function = resolve<decltype(&::name)>(#name);    \
        if (!function) {                                                   \
            failure;                                                       \
        }                                                                  \
        return function arguments;                                         \
    }

#define UFSECP_CL_ERROR return CL_INVALID_PLATFORM
#define UFSECP_CL_NULL(errcode_ret)                                        \
    if (errcode_ret) *errcode_ret = CL_INVALID_PLATFORM;                   \
    return nullptr

UFSECP_CL_FORWARD(cl_int, clGetPlatformIDs,
    (cl_uint num_entries, cl_platform_id* platforms, cl_uint* num_platforms),
    (num_entries, platforms, num_platforms),
    if (num_platforms) *num_platforms = 0; return CL_PLATFORM_NOT_FOUND_KHR)

UFSECP_CL_FORWARD(cl_int, clGetPlatformInfo,
    (cl_platform_id platform, cl_platform_info param_name, size_t param_value_size,
        void* param_value, size_t* param_value_size_ret),
    (platform, param_name, param_value_size, param_value, param_value_size_ret),
    UFSECP_CL_ERROR)

UFSECP_CL_FORWARD(cl_int, clGetDeviceIDs,
    (cl_platform_id platform, cl_device_type device_type, cl_uint num_entries,
        cl_device_id* devices, cl_uint* num_devices),
    (platform, device_type, num_entries, devices, num_devices),
    UFSECP_CL_ERROR)

UFSECP_CL_FORWARD(cl_int, clGetDeviceInfo,
    (cl_device_id device, cl_device_info param_name, size_t param_value_size,
        void* param_value, size_t* param_value_size_ret),
    (device, param_name, param_value_size, param_value, param_value_size_ret),
    UFSECP_CL_ERROR)

UFSECP_CL_FORWARD(cl_context, clCreateContext,
    (const cl_context_properties* properties, cl_uint num_devices, const cl_device_id* devices,
        void (CL_CALLBACK* pfn_notify)(const char*, const void*, size_t, void*),
        void* user_data, cl_int* errcode_ret),
    (properties, num_devices, devices, pfn_notify, user_data, errcode_ret),
    UFSECP_CL_NULL(errcode_ret))

UFSECP_CL_FORWARD(cl_int, clReleaseContext, (cl_context context), (context), UFSECP_CL_ERROR)

UFSECP_CL_FORWARD(cl_int, clGetContextInfo,
    (cl_context context, cl_context_info param_name, size_t param_value_size,
        void* param_value, size_t* param_value_size_ret),
    (context, param_name, param_value_size, param_value, param_value_size_ret),
    UFSECP_CL_ERROR)

UFSECP_CL_FORWARD(cl_command_queue, clCreateCommandQueue,
    (cl_context context, cl_device_id device, cl_command_queue_properties properties,
        cl_int* errcode_ret),
    (context, device, properties, errcode_ret),
    UFSECP_CL_NULL(errcode_ret))

UFSECP_CL_FORWARD(cl_int, clReleaseCommandQueue, (cl_command_queue command_queue),
    (command_queue), UFSECP_CL_ERROR)

UFSECP_CL_FORWARD(cl_int, clGetCommandQueueInfo,
    (cl_command_queue command_queue, cl_command_queue_info param_name, size_t param_value_size,
        void* param_value, size_t* param_value_size_ret),
    (command_queue, param_name, param_value_size, param_value, param_value_size_ret),
    UFSECP_CL_ERROR)

UFSECP_CL_FORWARD(cl_mem, clCreateBuffer,
    (cl_context context, cl_mem_flags flags, size_t size, void* host_ptr, cl_int* errcode_ret),
    (context, flags, size, host_ptr, errcode_ret),
    UFSECP_CL_NULL(errcode_ret))

UFSECP_CL_FORWARD(cl_int, clReleaseMemObject, (cl_mem memobj), (memobj), UFSECP_CL_ERROR)

UFSECP_CL_FORWARD(cl_program, clCreateProgramWithSource,
    (cl_context context, cl_uint count, const char** strings, const size_t* lengths,
        cl_int* errcode_ret),
    (context, count, strings, lengths, errcode_ret),
    UFSECP_CL_NULL(errcode_ret))

UFSECP_CL_FORWARD(cl_program, clCreateProgramWithBinary,
    (cl_context context, cl_uint num_devices, const cl_device_id* device_list,
        const size_t* lengths, const unsigned char** binaries, cl_int* binary_status,
        cl_int* errcode_ret),
    (context, num_devices, device_list, lengths, binaries, binary_status, errcode_ret),
    UFSECP_CL_NULL(errcode_ret))

UFSECP_CL_FORWARD(cl_int, clReleaseProgram, (cl_program program), (program), UFSECP_CL_ERROR)

UFSECP_CL_FORWARD(cl_int, clBuildProgram,
    (cl_program program, cl_uint num_devices, const cl_device_id* device_list, const char* options,
        void (CL_CALLBACK* pfn_notify)(cl_program, void*), void* user_data),
    (program, num_devices, device_list, options, pfn_notify, user_data),
    UFSECP_CL_ERROR)

UFSECP_CL_FORWARD(cl_int, clGetProgramInfo,
    (cl_program program, cl_program_info param_name, size_t param_value_size,
        void* param_value, size_t* param_value_size_ret),
    (program, param_name, param_value_size, param_value, param_value_size_ret),
    UFSECP_CL_ERROR)

UFSECP_CL_FORWARD(cl_int, clGetProgramBuildInfo,
    (cl_program program, cl_device_id device, cl_program_build_info param_name,
        size_t param_value_size, void* param_value, size_t* param_value_size_ret),
    (program, device, param_name, param_value_size, param_value, param_value_size_ret),
    UFSECP_CL_ERROR)

UFSECP_CL_FORWARD(cl_kernel, clCreateKernel,
    (cl_program program, const char* kernel_name, cl_int* errcode_ret),
    (program, kernel_name, errcode_ret),
    UFSECP_CL_NULL(errcode_ret))

UFSECP_CL_FORWARD(cl_int, clReleaseKernel, (cl_kernel kernel), (kernel), UFSECP_CL_ERROR)

UFSECP_CL_FORWARD(cl_int, clSetKernelArg,
    (cl_kernel kernel, cl_uint arg_index, size_t arg_size, const void* arg_value),
    (kernel, arg_index, arg_size, arg_value),
    UFSECP_CL_ERROR)

UFSECP_CL_FORWARD(cl_int, clGetKernelWorkGroupInfo,
    (cl_kernel kernel, cl_device_id device, cl_kernel_work_group_info param_name,
        size_t param_value_size, void* param_value, size_t* param_value_size_ret),
    (kernel, device, param_name, param_value_size, param_value, param_value_size_ret),
    UFSECP_CL_ERROR)

UFSECP_CL_FORWARD(cl_int, clWaitForEvents, (cl_uint num_events, const cl_event* event_list),
    (num_events, event_list), UFSECP_CL_ERROR)

UFSECP_CL_FORWARD(cl_int, clReleaseEvent, (cl_event event), (event), UFSECP_CL_ERROR)

UFSECP_CL_FORWARD(cl_int, clFlush, (cl_command_queue command_queue), (command_queue),
    UFSECP_CL_ERROR)

UFSECP_CL_FORWARD(cl_int, clFinish, (cl_command_queue command_queue), (command_queue),
    UFSECP_CL_ERROR)

UFSECP_CL_FORWARD(cl_int, clEnqueueReadBuffer,
    (cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_read, size_t offset,
        size_t size, void* ptr, cl_uint num_events_in_wait_list, const cl_event* event_wait_list,
        cl_event* event),
    (command_queue, buffer, blocking_read, offset, size, ptr, num_events_in_wait_list,
        event_wait_list, event),
    UFSECP_CL_ERROR)

UFSECP_CL_FORWARD(cl_int, clEnqueueWriteBuffer,
    (cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_write, size_t offset,
        size_t size, const void* ptr, cl_uint num_events_in_wait_list,
        const cl_event* event_wait_list, cl_event* event),
    (command_queue, buffer, blocking_write, offset, size, ptr, num_events_in_wait_list,
        event_wait_list, event),
    UFSECP_CL_ERROR)

UFSECP_CL_FORWARD(cl_int, clEnqueueFillBuffer,
    (cl_command_queue command_queue, cl_mem buffer, const void* pattern, size_t pattern_size,
        size_t offset, size_t size, cl_uint num_events_in_wait_list,
        const cl_event* event_wait_list, cl_event* event),
    (command_queue, buffer, pattern, pattern_size, offset, size, num_events_in_wait_list,
        event_wait_list, event),
    UFSECP_CL_ERROR)

UFSECP_CL_FORWARD(cl_int, clEnqueueNDRangeKernel,
    (cl_command_queue command_queue, cl_kernel kernel, cl_uint work_dim,
        const size_t* global_work_offset, const size_t* global_work_size,
        const size_t* local_work_size, cl_uint num_events_in_wait_list,
        const cl_event* event_wait_list, cl_event* event),
    (command_queue, kernel, work_dim, global_work_offset, global_work_size, local_work_size,
        num_events_in_wait_list, event_wait_list, event),
    UFSECP_CL_ERROR)
