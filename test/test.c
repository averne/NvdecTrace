#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <cuda.h>
#include <cuda_runtime.h>

#define CUDA_CHECK(expr) ({                                  \
    CUresult _err_ = (expr);                                 \
    if (_err_ != CUDA_SUCCESS) {                             \
        const char *str = NULL;                              \
        cuGetErrorString(_err_, &str);                       \
        printf(#expr ": failed with %s (%d)\n", str, _err_); \
    }                                                        \
})

#define SIZE 0x100000

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    printf("Starting\n");

    printf("Library init\n");
    CUDA_CHECK(cuInit(0));

    printf("Device init\n");
    CUdevice dev;
    CUDA_CHECK(cuDeviceGet(&dev, 0));

    int major, minor;
    cuDeviceGetAttribute(&major, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR, dev);
    cuDeviceGetAttribute(&minor, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR, dev);
    printf("Compute version: %d.%d\n", major, minor);

    printf("Context init\n");
    CUcontext ctx;
    CUDA_CHECK(cuCtxCreate(&ctx, CU_CTX_SCHED_BLOCKING_SYNC | CU_CTX_MAP_HOST, dev));

    char name[0x20];
    int driver_ver, api_ver;
    CUDA_CHECK(cuDriverGetVersion(&driver_ver));
    CUDA_CHECK(cuDeviceGetName(name, sizeof(name), dev));
    CUDA_CHECK(cuCtxGetApiVersion(ctx, &api_ver));
    printf("Device: %s, driver %d, api %d\n", name, driver_ver, api_ver);

    {
        CUdeviceptr devptr;
        printf("Device memory allocation\n");

        CUDA_CHECK(cuMemAlloc(&devptr, SIZE));
        printf("Device %#lx\n", devptr);
    }

    {
        void *mem;
        CUdeviceptr devptr;
        printf("Host memory mapping\n");

        mem = aligned_alloc(0x1000, SIZE);
        printf("Host %p\n", mem);

        CUDA_CHECK(cuMemHostRegister(mem, SIZE, CU_MEMHOSTREGISTER_DEVICEMAP));
        CUDA_CHECK(cuMemHostGetDevicePointer(&devptr, mem, 0));
        printf("Device %#lx\n", devptr);
    }

    {
        void *mem;
        CUdeviceptr devptr;
        printf("UVM allocation\n");
        CUDA_CHECK(cuMemAllocManaged(&devptr, SIZE, CU_MEM_ATTACH_HOST));
        printf("Device %#lx\n", devptr);
    }

    {
        printf("Memory alloc\n");
        CUdeviceptr devptr;
        CUDA_CHECK(cuMemAlloc(&devptr, SIZE));

        printf("Memset\n");
        CUDA_CHECK(cuMemsetD8(devptr, 0xcc, SIZE));

        printf("Sync\n");
        CUDA_CHECK(cuCtxSynchronize());
    }

    printf("Context deinit\n");
    CUDA_CHECK(cuCtxDestroy(ctx));

    return 0;
}
