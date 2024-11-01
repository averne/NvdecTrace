#include <cstdio>
#include <cstdint>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <list>
#include <mutex>
#include <ranges>
#include <set>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <vector>

#include <fcntl.h>
#include <dlfcn.h>
#include <signal.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <linux/ioctl.h>

#include <xxhash.h>
#include <capstone/capstone.h>

#include <clc7b0.h>
#include <clc7b5.h>
#include <nvdec_drv.h>

#include <nvmisc.h>
#include <nvos.h>
#include <nv_escape.h>
#include <alloc/alloc_channel.h>
#include <nv-unix-nvos-params-wrappers.h>
#include <uvm_linux_ioctl.h>
#include <nv-ioctl.h>

#include <cl0005.h>
#include <cl0070.h>
#include <cl0080.h>
#include <cl2080.h>
#include <cla16f.h>
#include <clc36f.h>
#include <ctrl2080.h>
#include <ctrl906f.h>
#include <ctrla06f.h>
#include <cl2080_notification.h>
#include <g_allclasses.h>

#include "names.hpp"

#define GPFIFO_VOLTA

#define SHOULD_LOG_FILES  0
#define SHOULD_LOG_MEM    0
#define SHOULD_LOG_POLL   0
#define SHOULD_LOG_IOCTL  0
#define SHOULD_LOG_GPFIFO 1
#define SHOULD_LOG_NVDEC  1

#define _LOG(fmt, ...) std::fprintf(stderr, fmt, ##__VA_ARGS__)

#define LOG_CLASS(c, fmt, ...)  ({ \
    if constexpr (SHOULD_LOG_##c)  \
        _LOG(fmt, ##__VA_ARGS__);  \
})

#define LOG_FILES(fmt, ...)  LOG_CLASS(FILES,  fmt, ##__VA_ARGS__)
#define LOG_MEM(fmt, ...)    LOG_CLASS(MEM,    fmt, ##__VA_ARGS__)
#define LOG_POLL(fmt, ...)   LOG_CLASS(POLL,   fmt, ##__VA_ARGS__)
#define LOG_IOCTL(fmt, ...)  LOG_CLASS(IOCTL,  fmt, ##__VA_ARGS__)
#define LOG_GPFIFO(fmt, ...) LOG_CLASS(GPFIFO, fmt, ##__VA_ARGS__)
#define LOG_NVDEC(fmt, ...)  LOG_CLASS(NVDEC,  fmt, ##__VA_ARGS__)

#define HEXDUMP(c, ...) ({        \
    if constexpr (SHOULD_LOG_##c) \
        hexdump(__VA_ARGS__);     \
})

#define HEXDUMPDW(c, ...) ({      \
    if constexpr (SHOULD_LOG_##c) \
        hexdumpdw(__VA_ARGS__);   \
})

#if defined(GPFIFO_KEPLER)
#define GPFIFO_CLASS A16F
#define GPFIFO_STRUCT KeplerBControlGPFifo
#elif defined(GPFIFO_VOLTA)
#define GPFIFO_CLASS C36F
#define GPFIFO_STRUCT VoltaAControlGPFifo
#else
#error "Need a GPFIFO architecture"
#endif

struct DmaAllocInfo {
    int fd                                 = 0;
    NvHandle mem_hdl                       = 0,
        va_hdl                             = 0;
    void *memory                           = nullptr;
    void *cpu_addr                         = nullptr;
    uint64_t gpu_addr                      = 0;
    size_t size                            = 0;
    bool is_mapped                         = false;
    std::vector<std::uint8_t> unmap_backup = {};
};

struct GpFifoInfo {
    NvHandle engine_hdl     = -1;
    DmaAllocInfo pushbuffer = {};
    uint64_t gpfifo_off     = 0;
    uint64_t gpfifo_entries = 0;
    std::uint32_t gpput     = 0;
    NvHandle userd_hdl      = -1;
    int userd_fd            = -2;
    void *userd_addr        = nullptr;
    uintptr_t userd_off     = 0;
};

struct MappingInfo {
    void *addr        = nullptr;
    size_t size       = 0;
    int fd            = 0;
    std::string fname = {};
};

using Digest = XXH64_hash_t;
#define DG_FMT "%016lx"
#define DG_UNPACK(d) __builtin_bswap64(d)


static csh capstonehdl = {};

static std::unordered_map<int, std::string>   g_map_files = {};
static std::unordered_map<void*, MappingInfo> g_fake_maps = {};

static std::list<DmaAllocInfo> g_dma_allocs    = {};
static std::vector<GpFifoInfo> g_nvdec_gpfifos = {};
static std::vector<GpFifoInfo> g_dma_gpfifos   = {};


using namespace std::string_view_literals;

bool is_address_valid(void *addr);
std::uint32_t find_cmdbuf_value(std::uint32_t *cmds, int len, std::uint32_t reg);
void *find_cmdbuf_alloc(std::uint32_t *cmds, int len, std::uint32_t reg);
Digest hash_buffer(void *buf, int buf_len);
Digest hash_cmdbuf_alloc(std::uint32_t *cmds, int len, std::uint32_t reg, int buf_len);
void hexdump(void *mem, unsigned int len, int indent = 0);
void hexdumpdw(void *mem, unsigned int len, int indent = 0);
int cs_to_uc(x86_reg reg);
std::size_t get_nvdec_codec_setup_size(int codec_id);
const char *get_nvdec_reg_name(std::uint32_t reg);
const char *get_dma_reg_name(std::uint32_t reg);
const char *get_class_name(std::uint32_t c);
const char *get_engine_name(std::uint32_t e);
const char *get_control_name(std::uint32_t id);


template <typename T>
GpFifoInfo *find_gpfifo(const T &pred) {
    auto gpfifo = std::ranges::find_if(g_nvdec_gpfifos, pred);
    if (gpfifo != g_nvdec_gpfifos.end())
        return &*gpfifo;

    gpfifo = std::ranges::find_if(g_dma_gpfifos, pred);
    if (gpfifo != g_dma_gpfifos.end())
        return &*gpfifo;

    return nullptr;
}

extern "C" int open(const char *pathname, int flags, ...) {
    static int (*real_open)(const char *pathname, int flags, ...) = nullptr;
    if (!real_open) real_open = reinterpret_cast<decltype(real_open)>(dlsym(RTLD_NEXT, "open"));

    void *args = __builtin_apply_args();
    void *res  = __builtin_apply(reinterpret_cast<void(*)(...)>((uintptr_t)real_open), args,
        (flags & (O_CREAT | O_TMPFILE)) ? 3 : 2);

    // This function can somehow be invoked before global constructors have been executed
    // Started happening with gcc 14.2?
    if (g_map_files.bucket_count())
        g_map_files[*(int *)res] = pathname;

    LOG_FILES("Opened %d (%s)\n", *(int *)res, pathname);

    __builtin_return(res);
}

extern "C" __attribute__((alias("open")))
int open64(const char *, int, ...) __THROW;

extern "C" int close(int fildes) {
    static int (*real_close)(int fildes) = nullptr;
    if (!real_close) real_close = reinterpret_cast<decltype(real_close)>(dlsym(RTLD_NEXT, "close"));

    int rc = real_close(fildes);

    if (g_map_files.contains(fildes)) {
        LOG_FILES("Closed %d (%s)\n", fildes, g_map_files[fildes].c_str());
        g_map_files.erase(fildes);
    }

    if (auto *gpfifo = find_gpfifo([&](auto &gp) { return gp.userd_fd == fildes; }); gpfifo)
        gpfifo->userd_fd = -2;

    return rc;
}

extern "C" void *mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off) {
    static void *(*real_mmap)(void *addr, size_t len, int prot, int flags, int fildes, off_t off) = nullptr;
    if (!real_mmap) real_mmap = reinterpret_cast<decltype(real_mmap)>(dlsym(RTLD_NEXT, "mmap"));

    void *res = real_mmap(addr, len, prot, flags, fildes, off);

    auto *gpfifo = find_gpfifo([&](auto &gp) { return gp.userd_fd == fildes; });
    bool should_mitm = gpfifo != nullptr;
    if (should_mitm) {
        void *fake = real_mmap(nullptr, len, PROT_NONE, MAP_SHARED | MAP_ANON, -1, 0);
        g_fake_maps[fake] = MappingInfo{res, len, fildes, g_map_files[fildes]};
        LOG_MEM("Injecting fake map for %s at %p, real %p -> fake %p\n", g_map_files[fildes].c_str(), addr, res, fake);

        gpfifo->userd_addr = res;
        res = fake;
    }

    if (auto alloc = std::ranges::find_if(g_dma_allocs, [&](auto &a) { return a.fd == fildes; }); alloc != g_dma_allocs.end())
        alloc->cpu_addr = res;

    LOG_MEM("Mapped fd %d (%s), addr %p -> %p, len:off %#lx:%#lx, prot %#x, flags %#x\n", fildes,
        g_map_files.contains(fildes) ? g_map_files[fildes].c_str() : "unknown",
        addr, res, len, off, prot, flags);

    return res;
}

extern "C" __attribute__((alias("mmap")))
void *mmap64(void *, size_t, int, int, int, off64_t) __THROW;

extern "C" int munmap(void *addr, size_t len) {
    static int (*real_munmap)(void *addr, size_t len) = nullptr;
    if (!real_munmap) real_munmap = reinterpret_cast<decltype(real_munmap)>(dlsym(RTLD_NEXT, "munmap"));

    int res = real_munmap(addr, len);

    LOG_MEM("Unmapped range at addr %p, len %#lx\n", addr, len);

    return res;
}

extern "C" int poll(struct pollfd fds[], nfds_t nfds, int timeout) {
    static int (*real_poll)(struct pollfd fds[], nfds_t nfds, int timeout) = nullptr;
    if (!real_poll) real_poll = reinterpret_cast<decltype(real_poll)>(dlsym(RTLD_NEXT, "poll"));

    int res = real_poll(fds, nfds, timeout);

    LOG_POLL("Poll on %lu files, timeout %d\n", nfds, timeout);

    for (auto i = 0u; i < nfds; ++i) {
        auto &p = fds[i];
        LOG_POLL("  fd %d (%s), events %#x, revents %#x\n",
            p.fd, g_map_files.contains(p.fd) ? g_map_files[p.fd].c_str() : "unknown",
            p.events, p.revents);
    }

    return res;
}

extern "C" int ioctl(int fildes, int request, void *arg) {
    static void *(*real_ioctl)(int fildes, int request, void *arg) = nullptr;
    if (!real_ioctl) real_ioctl = reinterpret_cast<decltype(real_ioctl)>(dlsym(RTLD_NEXT, "ioctl"));

    void *args = __builtin_apply_args();
    void *res  = __builtin_apply(reinterpret_cast<void(*)(...)>((uintptr_t)real_ioctl), args, 3);

    auto type = _IOC_TYPE(request), dir = _IOC_DIR(request),
        nr = _IOC_NR(request), size = _IOC_SIZE(request);

    LOG_IOCTL("Ioctl on %d (%s): req %#010x (type %d '%c', dir %d, nr %#x, size %#x)\n", fildes,
        g_map_files.contains(fildes) ? g_map_files[fildes].c_str() : "unknown",
        request, type, type ?: ' ', dir, nr, size);

    switch (nr) {
        case NV_ESC_RM_ALLOC_MEMORY: {
            auto *params = static_cast<nv_ioctl_nvos02_parameters_with_fd *>(arg);

            if (auto alloc = std::ranges::find_if(g_dma_allocs, [&](auto &a) { return a.mem_hdl == params->params.hObjectNew; }); alloc != g_dma_allocs.end()) {
                alloc->fd = params->fd, alloc->memory = params->params.pMemory;
                g_dma_allocs.splice(g_dma_allocs.begin(), g_dma_allocs, alloc, std::next(alloc));
            } else {
                g_dma_allocs.push_front(DmaAllocInfo{
                    .fd      = params->fd,
                    .mem_hdl = params->params.hObjectNew,
                    .memory  = params->params.pMemory,
                });
            }

            LOG_IOCTL("  Dma mem alloc: root %#x, parent %#x, handle %#x, class %#x, flags %#x, mem %p, limit %#llx, fd %d (%s)\n",
                params->params.hRoot, params->params.hObjectParent, params->params.hObjectNew, params->params.hClass, params->params.flags, params->params.pMemory, params->params.limit,
                params->fd, g_map_files.contains(params->fd) ? g_map_files[params->fd].c_str() : "unknown");
            break;
        }
        case NV_ESC_RM_MAP_MEMORY_DMA: {
            auto *params = static_cast<NVOS46_PARAMETERS *>(arg);

            if (auto alloc = std::ranges::find_if(g_dma_allocs, [&](auto &a) { return a.mem_hdl == params->hMemory; }); alloc != g_dma_allocs.end())
                alloc->va_hdl = params->hDma, alloc->size = params->length, alloc->gpu_addr = params->dmaOffset;

            LOG_IOCTL("  Dma mem map: root %#x, device %#x, dma %#x, mem %#x, offset %#llx, length %#llx, flags %#x, dma offset %#llx\n",
                params->hClient, params->hDevice, params->hDma, params->hMemory, params->offset, params->length, params->flags, params->dmaOffset);
            break;
        }
        case NV_ESC_RM_UNMAP_MEMORY_DMA: {
            auto *params = static_cast<NVOS47_PARAMETERS *>(arg);
            LOG_IOCTL("  Dma mem unmap: root %#x, device %#x, dma %#x, mem %#x, flags %#x, dma offset %#llx\n",
                params->hClient, params->hDevice, params->hDma, params->hMemory, params->flags, params->dmaOffset);
            break;
        }
        case NV_ESC_ALLOC_OS_EVENT: {
            auto *params = static_cast<nv_ioctl_alloc_os_event_t *>(arg);
            LOG_IOCTL("  OSEvent alloc: root %#x, device %#x, fd %u\n",
                params->hClient, params->hDevice, params->fd);
            break;
        }
        case NV_ESC_FREE_OS_EVENT: {
            auto *params = static_cast<nv_ioctl_free_os_event_t *>(arg);
            LOG_IOCTL("  OSEvent free: root %#x, device %#x, fd %u\n",
                params->hClient, params->hDevice, params->fd);
            break;
        }
        case NV_ESC_RM_ALLOC: {
            void *alloc_params = nullptr;
            NvHandle hnew      = 0;
            uint32_t hclass    = 0;

            if (size == sizeof(NVOS21_PARAMETERS)) {
                auto *params = static_cast<NVOS21_PARAMETERS *>(arg);
                alloc_params = params->pAllocParms, hnew = params->hObjectNew, hclass = params->hClass;

                LOG_IOCTL("  Alloc: class %#x (%s), root %#x, parent %#x, handle %#x, alloc params: %p, size %#x\n",
                    params->hClass, get_class_name(params->hClass), params->hRoot, params->hObjectParent, params->hObjectNew, params->pAllocParms, params->paramsSize);
            } else if (size == sizeof(NVOS64_PARAMETERS)) {
                auto *params = static_cast<NVOS64_PARAMETERS *>(arg);
                alloc_params = params->pAllocParms, hnew = params->hObjectNew, hclass = params->hClass;

                LOG_IOCTL("  Alloc: class %#x (%s), root %#x, parent %#x, handle %#x, flags %#x, alloc params: %p, size %#x\n",
                    params->hClass, get_class_name(params->hClass), params->hRoot, params->hObjectParent, params->hObjectNew, params->flags, params->pAllocParms, params->paramsSize);
            }

            if (!alloc_params)
                break;

            switch (hclass) {
                case MAXWELL_CHANNEL_GPFIFO_A:
                case AMPERE_CHANNEL_GPFIFO_A: {
                    auto *params = static_cast<NV_CHANNEL_ALLOC_PARAMS *>(alloc_params);

                    if (params->engineType == NV2080_ENGINE_TYPE_NVDEC0) {
                        auto pred = [&](DmaAllocInfo &a) { return params->gpFifoOffset == a.gpu_addr + params->gpFifoEntries * 64; };

                        if (auto alloc = std::ranges::find_if(g_dma_allocs, pred); alloc != g_dma_allocs.end()) {
                            g_nvdec_gpfifos.push_back({
                                .engine_hdl     = hnew,
                                .pushbuffer     = *alloc,
                                .gpfifo_off     = params->gpFifoOffset,
                                .gpfifo_entries = params->gpFifoEntries,
                                .userd_hdl      = params->hUserdMemory[0],
                                .userd_off      = params->userdOffset[0],
                            });
                        }
                    }

                    if (params->engineType == NV2080_ENGINE_TYPE_COPY2) {
                        auto pred = [&](DmaAllocInfo &a) { return params->gpFifoOffset == a.gpu_addr + params->gpFifoEntries * 64; };

                        if (auto alloc = std::ranges::find_if(g_dma_allocs, pred); alloc != g_dma_allocs.end()) {
                            g_dma_gpfifos.push_back({
                                .engine_hdl     = hnew,
                                .pushbuffer     = *alloc,
                                .gpfifo_off     = params->gpFifoOffset,
                                .gpfifo_entries = params->gpFifoEntries,
                                .userd_hdl      = params->hUserdMemory[0],
                                .userd_off      = params->userdOffset[0],
                            });
                        }
                    }

                    LOG_IOCTL("    GPFIFO alloc: engine type %#x (%s), subdevice %#x, error hdl %#x, vaspace hdl %#x, ctxshare hdl %#x, num entries: %#x, offset %#llx, userd mem hdl/offset %#x/%#llx\n",
                        params->engineType, get_engine_name(params->engineType), params->subDeviceId, params->hObjectError,
                        params->hVASpace, params->hContextShare, params->gpFifoEntries, params->gpFifoOffset,
                        params->hUserdMemory[0], params->userdOffset[0]);
                    break;
                }
                case NV01_DEVICE_0: {
                    auto *params = static_cast<NV0080_ALLOC_PARAMETERS *>(alloc_params);
                    LOG_IOCTL("    Device alloc: dev id %u, client share hdl %#x, target client hdl %#x, target dev hdl %#x, flags %#x, vaspace size %#llx, va mode %u\n",
                        params->deviceId, params->hClientShare, params->hTargetClient, params->hTargetDevice, params->flags, params->vaSpaceSize, params->vaMode);
                    break;
                }
                case NV20_SUBDEVICE_0: {
                    auto *params = static_cast<NV2080_ALLOC_PARAMETERS *>(alloc_params);
                    LOG_IOCTL("    Subdevice alloc: subdev id %u\n",
                        params->subDeviceId);
                    break;
                }
                case NV01_MEMORY_VIRTUAL: {
                    auto *params = static_cast<NV_MEMORY_VIRTUAL_ALLOCATION_PARAMS *>(alloc_params);
                    LOG_IOCTL("    VA context alloc: va space %#x, offset %#llx, limit %#llx\n",
                        params->hVASpace, params->offset, params->limit);
                    break;
                }
                case NV01_CONTEXT_DMA: {
                    auto *params = static_cast<NV_CONTEXT_DMA_ALLOCATION_PARAMS *>(alloc_params);
                    LOG_IOCTL("    DMA alloc: subdevice %#x, memory %#x, flags %#x, offset %#llx, limit %#llx\n",
                        params->hSubDevice, params->hMemory, params->flags, params->offset, params->limit);
                    break;
                }
                case NV01_MEMORY_SYSTEM: {
                case NV01_MEMORY_LOCAL_USER:
                case NV50_MEMORY_VIRTUAL:
                    auto *params = static_cast<NV_MEMORY_ALLOCATION_PARAMS *>(alloc_params);

                    if (auto alloc = std::ranges::find_if(g_dma_allocs, [&](auto &a) { return a.mem_hdl == hnew; }); alloc != g_dma_allocs.end()) {
                        alloc->size = params->size;
                        g_dma_allocs.splice(g_dma_allocs.begin(), g_dma_allocs, alloc, std::next(alloc));
                    } else {
                        g_dma_allocs.push_front(DmaAllocInfo{
                            .mem_hdl = hnew,
                            .size    = params->size,
                        });
                    }

                    LOG_IOCTL("    Mem alloc: class %#x, owner %#x, type %#x, attributes %#x/%#x, flags %#x, vaspace %#x, offset %#llx, size %#llx, align %#llx, whp: %ux%u-%d\n", hclass,
                        params->owner, params->type, params->attr, params->attr2, params->flags, params->hVASpace, params->offset, params->size, params->alignment, params->width, params->height, params->pitch);
                    break;
                }
                case FERMI_VASPACE_A: {
                    auto *params = static_cast<NV_VASPACE_ALLOCATION_PARAMETERS *>(alloc_params);
                    LOG_IOCTL("    Vaspace alloc: index %u, flags %#x, base %#llx, size %#llx, big page size %#x\n",
                        params->index, params->flags, params->vaBase, params->vaSize, params->bigPageSize);
                    break;
                }
                case NV01_EVENT_OS_EVENT: {
                    auto *params = static_cast<NV0005_ALLOC_PARAMETERS *>(alloc_params);
                    LOG_IOCTL("    Event alloc: client hdl %#x, src hdl %#x, class %#x, notify idx %#x, data %p\n",
                        params->hParentClient, params->hSrcResource, params->hClass, params->notifyIndex, params->data);
                    break;
                }
                default:
                    break;
            }
            break;
        }
        case NV_ESC_RM_FREE: {
            auto *params = static_cast<NVOS00_PARAMETERS *>(arg);
            LOG_IOCTL("  Free: handle %#x, parent %#x\n", params->hObjectOld, params->hObjectParent);
            break;
        }
        case NV_ESC_RM_CONTROL: {
            auto *params = static_cast<NVOS54_PARAMETERS *>(arg);
            LOG_IOCTL("  Control: cmd %#x (%s), handle %#x\n", params->cmd, get_control_name(params->cmd), params->hObject);

            switch (params->cmd) {
                case NVA06F_CTRL_CMD_BIND: {
                    auto *bindparams = static_cast<NVA06F_CTRL_BIND_PARAMS *>(params->params);
                    LOG_IOCTL("    Bind engine %#x (%s)\n", bindparams->engineType, get_engine_name(bindparams->engineType));
                    break;
                }
                case NVA06F_CTRL_CMD_GPFIFO_SCHEDULE: {
                    auto *schedparams = static_cast<NVA06F_CTRL_GPFIFO_SCHEDULE_PARAMS *>(params->params);
                    LOG_IOCTL("    Schedule engine: enable %d, skip submit %d\n", schedparams->bEnable, schedparams->bSkipSubmit);
                    break;
                }
            }

            break;
        }
        case NV_ESC_RM_MAP_MEMORY: {
            auto *params = static_cast<nv_ioctl_nvos33_parameters_with_fd *>(arg);

#if defined(GPFIFO_KEPLER)
            auto pred = [&](auto &gp) { return gp.engine_hdl == params->params.hMemory; };
#elif defined(GPFIFO_VOLTA)
            auto pred = [&](auto &gp) { return gp.userd_hdl  == params->params.hMemory; };
#endif

            if (auto gpfifo = find_gpfifo(pred); gpfifo)
                gpfifo->userd_fd = params->fd, gpfifo->userd_off = (uintptr_t)params->params.pLinearAddress & 0xfff;

            if (auto alloc = std::ranges::find_if(g_dma_allocs, [&](auto &a) { return a.mem_hdl == params->params.hMemory; }); alloc != g_dma_allocs.end())
                alloc->fd = params->fd, alloc->memory = params->params.pLinearAddress, alloc->is_mapped = true;

            LOG_IOCTL("  Map: fd %d, handle %#x, offset %#llx, size %#llx, address %p\n", params->fd,
                params->params.hMemory, params->params.offset, params->params.length, params->params.pLinearAddress);
            break;
        }
        case NV_ESC_RM_UNMAP_MEMORY: {
            auto *params = static_cast<NVOS34_PARAMETERS *>(arg);

            if (auto alloc = std::ranges::find_if(g_dma_allocs, [&](auto &a) { return a.mem_hdl == params->hMemory; }); alloc != g_dma_allocs.end()) {
                alloc->is_mapped = false;
                if (is_address_valid(alloc->cpu_addr)) {
                    alloc->unmap_backup.resize(alloc->size);
                    std::memcpy(&*alloc->unmap_backup.begin(), alloc->cpu_addr, alloc->size);
                } else {
                    LOG_IOCTL("Invalid address, skipping backup\n");
                }
            }

            LOG_IOCTL("  Unmap: client hdl %#x, device hdl %#x, mem hdl %#x, address %p, flags %#x\n",
                params->hClient, params->hDevice, params->hMemory, params->pLinearAddress, params->flags);
            break;
        }
        case _IOC_NR(UVM_INITIALIZE): {
            auto *params = static_cast<UVM_INITIALIZE_PARAMS *>(arg);
            LOG_IOCTL("  UVM init: flags %#llx\n", params->flags);
            break;
        }
        case _IOC_NR(UVM_MM_INITIALIZE): {
            auto *params = static_cast<UVM_MM_INITIALIZE_PARAMS *>(arg);
            LOG_IOCTL("  UVM mm init: fd %d\n", params->uvmFd);
            break;
        }
        case _IOC_NR(UVM_REGISTER_GPU): {
            auto *params = static_cast<UVM_REGISTER_GPU_PARAMS *>(arg);
            LOG_IOCTL("  UVM gpu register: numa en %d, numa node id %d, rmctrl fd %d, client hdl %#x, smc part ref hdl %#x\n",
                params->numaEnabled, params->numaNodeId, params->rmCtrlFd, params->hClient, params->hSmcPartRef);
            break;
        }
        case _IOC_NR(UVM_REGISTER_GPU_VASPACE): {
            auto *params = static_cast<UVM_REGISTER_GPU_VASPACE_PARAMS *>(arg);
            LOG_IOCTL("  UVM gpu vaspace register: rmctrl fd %d, client hdl %#x, vaspace hdl %#x\n",
                params->rmCtrlFd, params->hClient, params->hVaSpace);
            break;
        }
        case _IOC_NR(UVM_UNREGISTER_GPU_VASPACE): {
            LOG_IOCTL("  UVM gpu vaspace unregister\n");
            break;
        }
        case _IOC_NR(UVM_REGISTER_CHANNEL): {
            auto *params = static_cast<UVM_REGISTER_CHANNEL_PARAMS *>(arg);
            LOG_IOCTL("  UVM gpu channel register: rmctrl fd %d, client hdl %#x, channel hdl %#x, base %#llx, length %#llx\n",
                params->rmCtrlFd, params->hClient, params->hChannel, params->base, params->length);
            break;
        }
        case _IOC_NR(UVM_UNREGISTER_CHANNEL): {
            auto *params = static_cast<UVM_UNREGISTER_CHANNEL_PARAMS *>(arg);
            LOG_IOCTL("  UVM gpu channel unregister: client hdl %#x, channel hdl %#x\n",
                params->hClient, params->hChannel);
            break;
        }
        case _IOC_NR(UVM_CREATE_EXTERNAL_RANGE): {
            auto *params = static_cast<UVM_CREATE_EXTERNAL_RANGE_PARAMS *>(arg);
            LOG_IOCTL("  UVM external range create: base %#llx, length %#llx\n", params->base, params->length);
            break;
        }
        case _IOC_NR(UVM_MAP_EXTERNAL_ALLOCATION): {
            auto *params = static_cast<UVM_MAP_EXTERNAL_ALLOCATION_PARAMS *>(arg);
            LOG_IOCTL("  UVM external alloc map: rmctrl fd %d, client hdl %#x, memory hdl %#x, num attrs %llu, base %#llx, off %#llx, length %#llx\n",
                params->rmCtrlFd, params->hClient, params->hMemory, params->gpuAttributesCount, params->base, params->offset, params->length);
            for (auto i = 0ull; i < params->gpuAttributesCount; ++i) {
                LOG_IOCTL("    Attribute %llu: mapping type %u, caching type %u, format type %u, element bits %u, compression type %u\n", i,
                    params->perGpuAttributes[i].gpuMappingType, params->perGpuAttributes[i].gpuCachingType, params->perGpuAttributes[i].gpuFormatType,
                    params->perGpuAttributes[i].gpuElementBits, params->perGpuAttributes[i].gpuCompressionType);
            }
            break;
        }
        case _IOC_NR(UVM_FREE): {
            auto *params = static_cast<UVM_FREE_PARAMS *>(arg);
            LOG_IOCTL("  UVM free: base %#llx, length %#llx\n", params->base, params->length);
            break;
        }
        default:
            break;
    }

    __builtin_return(res);
}

void handle_nvdec_kickoff(GpFifoInfo *gpfifo, greg_t entries_off) {
    LOG_GPFIFO("Nvdec kickoff detected with offset %#llx\n", entries_off);

    for (std::uint32_t gp = gpfifo->gpput; gp < (entries_off ?: gpfifo->gpfifo_entries); gp += 1) {
        uint32_t *entries = (uint32_t *)((uintptr_t)gpfifo->pushbuffer.cpu_addr + (gpfifo->gpfifo_off - gpfifo->pushbuffer.gpu_addr) + gp * NVA16F_GP_ENTRY__SIZE);

        auto off = (DRF_VAL64(A16F, _GP_ENTRY0, _GET, entries[0]) << 2) | (DRF_VAL64(A16F, _GP_ENTRY1, _GET_HI, entries[1]) << 32);
        auto len = DRF_VAL(A16F, _GP_ENTRY1, _LENGTH, entries[1]);
        LOG_GPFIFO("  Gpfifo entries: %#010x %#010x -> off %#llx, len %#x\n", entries[0], entries[1], off, len);

        uint32_t *cmds = (uint32_t *)((uintptr_t )gpfifo->pushbuffer.cpu_addr + (off - gpfifo->pushbuffer.gpu_addr));
        HEXDUMPDW(GPFIFO, cmds, len, 2);

        for (uint32_t i = 0; i < len; ++i) {
            auto c = cmds[i];
            auto op = DRF_VAL(A16F, _DMA, _SEC_OP, c), size = DRF_VAL(A16F, _DMA, _METHOD_COUNT, c),
                subchan = DRF_VAL(A16F, _DMA, _METHOD_SUBCHANNEL, c), method = DRF_VAL(A16F, _DMA, _METHOD_ADDRESS, c) << 2;
            LOG_GPFIFO("  Method %#06x (%#010x): type %d, size %x, subchannel %d, reg %#010x (%s)\n", i, c, op, size, subchan, method, get_nvdec_reg_name(method));

            if ((op != NVA16F_DMA_SEC_OP_INC_METHOD) && (op != NVA16F_DMA_SEC_OP_ONE_INC))
                continue;

            auto stop = i + size;
            for (; i < stop; ++i)
                LOG_GPFIFO("    %#010x\n", cmds[i+1]);
        }

        std::uint32_t v;
        void *addr;
        Digest digest;

        v = find_cmdbuf_value(cmds, len, NVC7B0_SET_PICTURE_INDEX);
        if (v == -1u)
            continue;

        LOG_NVDEC("Picture index %#010x\n", v);

        v = find_cmdbuf_value(cmds, len, NVC7B0_SET_CONTROL_PARAMS);
        if (v != -1u)
            LOG_NVDEC("Control params %#010x: codec %d, gptimer %d, ret error %d, err conceal %d, error frame idx %d, mbtimer %d, ec intra %d, all intra %d\n",
                v,
                DRF_VAL(C7B0, _SET_CONTROL_PARAMS, _CODEC_TYPE,                v), DRF_VAL(C7B0, _SET_CONTROL_PARAMS, _GPTIMER_ON,      v),
                DRF_VAL(C7B0, _SET_CONTROL_PARAMS, _RET_ERROR,                 v), DRF_VAL(C7B0, _SET_CONTROL_PARAMS, _ERR_CONCEAL_ON,  v),
                DRF_VAL(C7B0, _SET_CONTROL_PARAMS, _ERROR_FRM_IDX,             v), DRF_VAL(C7B0, _SET_CONTROL_PARAMS, _MBTIMER_ON,      v),
                DRF_VAL(C7B0, _SET_CONTROL_PARAMS, _EC_INTRA_FRAME_USING_PSLC, v), DRF_VAL(C7B0, _SET_CONTROL_PARAMS, _ALL_INTRA_FRAME, v));

        auto sz = get_nvdec_codec_setup_size(DRF_VAL(C7B0, _SET_CONTROL_PARAMS, _CODEC_TYPE, v));
        addr = find_cmdbuf_alloc(cmds, len, NVC7B0_SET_DRV_PIC_SETUP_OFFSET);
        if (addr) {
            digest = hash_buffer(addr, sz);
            LOG_NVDEC("Picture setup: " DG_FMT "\n", DG_UNPACK(digest));
            HEXDUMP(NVDEC, addr, sz, 1);
        }

        addr = find_cmdbuf_alloc(cmds, len, NVC7B0_SET_IN_BUF_BASE_OFFSET);
        if (addr) {
            digest = hash_buffer(addr, 0x100);
            LOG_NVDEC("Bitstream: " DG_FMT "\n", DG_UNPACK(digest));
            HEXDUMP(NVDEC, addr, 0x100, 1);
        }

        addr = find_cmdbuf_alloc(cmds, len, NVC7B0_SET_SLICE_OFFSETS_BUF_OFFSET);
        if (addr) {
            digest = hash_buffer(addr, 0x100);
            LOG_NVDEC("Slice offsets: " DG_FMT "\n", DG_UNPACK(digest));
            HEXDUMPDW(NVDEC, addr, 0x40, 1);
        }

        LOG_NVDEC("Maps:\n");

        for (int i = 0; i < 3; ++i)
            LOG_NVDEC("  Luma %d: %#010x, Chroma %d: %#010x\n",
                i, find_cmdbuf_value(cmds, len, NVC7B0_SET_PICTURE_LUMA_OFFSET0   + 4*i),
                i, find_cmdbuf_value(cmds, len, NVC7B0_SET_PICTURE_CHROMA_OFFSET0 + 4*i));

        LOG_NVDEC("  Coloc: %#010x, History: %#010x\n",
            find_cmdbuf_value(cmds, len, NVC7B0_SET_COLOC_DATA_OFFSET),
            find_cmdbuf_value(cmds, len, NVC7B0_SET_HISTORY_OFFSET));

        // digest = hash_cmdbuf_alloc(cmds, len, NVC7B0_SET_COLOC_DATA_OFFSET,      0x1000);
        // LOG_NVDEC("Coloc:   " DG_FMT "\n", DG_UNPACK(digest));

        // digest = hash_cmdbuf_alloc(cmds, len, NVC7B0_SET_PIC_SCRATCH_BUF_OFFSET, 0x200);
        // LOG_NVDEC("Scratch: " DG_FMT "\n", DG_UNPACK(digest));
    }

    LOG_GPFIFO("\n");

    gpfifo->gpput = entries_off;
}

void handle_dma_kickoff(GpFifoInfo *gpfifo, greg_t entries_off) {
    LOG_GPFIFO("Dma kickoff detected with offset %#llx\n", entries_off);

    for (std::uint32_t gp = gpfifo->gpput; gp < (entries_off ?: gpfifo->gpfifo_entries); gp += 1) {
        uint32_t *entries = (uint32_t *)((uintptr_t)gpfifo->pushbuffer.cpu_addr + (gpfifo->gpfifo_off - gpfifo->pushbuffer.gpu_addr) + gp * NVA16F_GP_ENTRY__SIZE);

        auto off = (DRF_VAL64(A16F, _GP_ENTRY0, _GET, entries[0]) << 2) | (DRF_VAL64(A16F, _GP_ENTRY1, _GET_HI, entries[1]) << 32);
        auto len = DRF_VAL(A16F, _GP_ENTRY1, _LENGTH, entries[1]);
        LOG_GPFIFO("  Gpfifo entries: %#010x %#010x -> off %#llx, len %#x\n", entries[0], entries[1], off, len);

        uint32_t *cmds = (uint32_t *)((uintptr_t )gpfifo->pushbuffer.cpu_addr + (off - gpfifo->pushbuffer.gpu_addr));
        HEXDUMPDW(GPFIFO, cmds, len, 2);

        for (uint32_t i = 0; i < len; ++i) {
            auto c = cmds[i];
            auto op = DRF_VAL(A16F, _DMA, _SEC_OP, c), size = DRF_VAL(A16F, _DMA, _METHOD_COUNT, c),
                subchan = DRF_VAL(A16F, _DMA, _METHOD_SUBCHANNEL, c), method = DRF_VAL(A16F, _DMA, _METHOD_ADDRESS, c) << 2;
            LOG_GPFIFO("  Method %#06x (%#010x): type %d, size %x, subchannel %d, reg %#010x (%s)\n", i, c, op, size, subchan, method, get_dma_reg_name(method));

            if ((op != NVA16F_DMA_SEC_OP_INC_METHOD) && (op != NVA16F_DMA_SEC_OP_ONE_INC))
                continue;

            auto stop = i + size;
            for (; i < stop; ++i)
                LOG_GPFIFO("    %#010x\n", cmds[i+1]);
        }
    }

    LOG_GPFIFO("\n");

    gpfifo->gpput = entries_off;
}

void segfault_handler(__attribute__((unused)) int sig, siginfo_t *si, void *unused) {
    ucontext_t *u = (ucontext_t *)unused;

    MappingInfo real = {};
    void *fake_base = nullptr;
    for (auto &MappingInfo: g_fake_maps) {
        auto fake = MappingInfo.first;
        auto map = MappingInfo.second;
        if (fake <= si->si_addr && si->si_addr <= static_cast<std::uint8_t *>(fake) + map.size) {
            real = map, fake_base = fake;
            break;
        }
    }

    if (!real.addr) {
        std::fprintf(stderr, "Segfault at %p\n", si->si_addr);
        exit(-1);
    }

    auto real_addr = reinterpret_cast<uintptr_t>(si->si_addr)
        - reinterpret_cast<uintptr_t>(fake_base)
        + reinterpret_cast<uintptr_t>(real.addr);

    auto rip = u->uc_mcontext.gregs[REG_RIP];
    LOG_MEM("Intercepted access @ %#llx to fake %p -> real %#lx (%s)\n", rip, si->si_addr, real_addr, real.fname.c_str());

    cs_insn *insn;
    auto count = cs_disasm(capstonehdl, reinterpret_cast<std::uint8_t *>(rip), 0x10, rip, 0, &insn);

    if (insn->mnemonic != "mov"sv) {
        std::fprintf(stderr, "Unhandled memory instruction %s\n", insn->mnemonic);
        exit(-1);
    }

    int reg = 0, disp = 0;
    auto &x86 = insn->detail->x86;
    for (auto &op: x86.operands) {
        if (op.type == X86_OP_MEM) {
            reg = cs_to_uc(op.mem.base), disp = op.mem.disp;
            break;
        }
    }

    if (x86.op_count == 2) {
        auto &op1 = x86.operands[0], op2 = x86.operands[1];

        if ((op1.type == X86_OP_MEM) && (op1.mem.disp == offsetof(GPFIFO_STRUCT, GPPut))) {
            auto pred = [&](GpFifoInfo &gp) {
                auto addr = (uintptr_t)gp.userd_addr + gp.userd_off;
                return addr <= real_addr && real_addr < addr + sizeof(GPFIFO_STRUCT);
            };

            GpFifoInfo *gpfifo;
            auto entries_off = u->uc_mcontext.gregs[cs_to_uc(op2.reg)];

            gpfifo = std::ranges::find_if(g_nvdec_gpfifos, pred).base();
            if (gpfifo && real_addr - offsetof(GPFIFO_STRUCT, GPPut) == (uintptr_t)gpfifo->userd_addr + gpfifo->userd_off)
                handle_nvdec_kickoff(gpfifo, entries_off);

            gpfifo = std::ranges::find_if(g_dma_gpfifos, pred).base();
            if (gpfifo && real_addr - offsetof(GPFIFO_STRUCT, GPPut) == (uintptr_t)gpfifo->userd_addr + gpfifo->userd_off)
                handle_dma_kickoff(gpfifo, entries_off);
        }
    }

    cs_free(insn, count);

    LOG_MEM("Forwarding memory access for inst \"%s %s\" (%d -> %#lx)\n",
        insn->mnemonic, insn->op_str, reg, real_addr);

    u->uc_mcontext.gregs[reg] = real_addr - disp;
}

__attribute__((constructor))
void entry() {
    cs_open(CS_ARCH_X86, CS_MODE_64, &capstonehdl);
    cs_option(capstonehdl, CS_OPT_DETAIL, CS_OPT_ON);

    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = segfault_handler;
    sigaction(SIGSEGV, &sa, nullptr);
    LOG_MEM("Registered segfault handler\n");
}

bool is_address_valid(void *addr) {
    std::uint64_t dummy;
    struct iovec rvec = { addr, sizeof(dummy) }, lvec = { &dummy, sizeof(dummy) };
    auto ret = process_vm_readv(getpid(), &lvec, 1, &rvec, 1, 0);
    return !(ret == -1 && errno == EFAULT);
}

std::uint32_t find_cmdbuf_value(std::uint32_t *cmds, int len, std::uint32_t reg) {
    for (int i = 0; i < len; ++i) {
        auto c = cmds[i];
        auto op = DRF_VAL(A16F, _DMA, _SEC_OP, c), size = DRF_VAL(A16F, _DMA, _METHOD_COUNT, c),
            method = DRF_VAL(A16F, _DMA, _METHOD_ADDRESS, c) << 2;

        if ((op != NVA16F_DMA_SEC_OP_INC_METHOD) && (op != NVA16F_DMA_SEC_OP_ONE_INC))
            continue;

        if (method == reg)
            return cmds[i+1];

        i += size;
    }

    return -1;
}

void *find_cmdbuf_alloc(std::uint32_t *cmds, int len, std::uint32_t reg) {
    std::uint64_t iova = find_cmdbuf_value(cmds, len, reg);
    if (iova == -1u)
        return nullptr;

    iova <<= 8;

    auto pred = [&](DmaAllocInfo &a) {
        return a.gpu_addr <= iova && iova < a.gpu_addr + a.size;
    };

    if (auto alloc = std::ranges::find_if(g_dma_allocs, pred); alloc != g_dma_allocs.end()) {
        auto *base = alloc->is_mapped ? (uint8_t *)alloc->cpu_addr : &*alloc->unmap_backup.begin();
        return base + iova - alloc->gpu_addr;
    }

    return nullptr;
}

Digest hash_buffer(void *buf, int buf_len) {
    return XXH64(buf, buf_len, 0);
}

Digest hash_cmdbuf_alloc(std::uint32_t *cmds, int len, std::uint32_t reg, int buf_len) {
    if (auto buf = find_cmdbuf_alloc(cmds, len, reg); buf != nullptr)
        return hash_buffer(buf, buf_len);
    return {};
}

#define HEXDUMP_COLS 16
void hexdump(void *mem, unsigned int len, int indent) {
    for (unsigned int i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++) {
        if (i % HEXDUMP_COLS == 0)
            fprintf(stderr, "%*dx%06x: ", indent*2+1, 0, i);

        if (i < len)
            fprintf(stderr, "%02x ", 0xFF & ((char*)mem)[i]);
        else
            fprintf(stderr, "   ");

        if (i % HEXDUMP_COLS == (HEXDUMP_COLS - 1)) {
            for (unsigned int j = i - (HEXDUMP_COLS - 1); j <= i; j++) {
                if (j >= len)
                    fputc(' ', stderr);
                else if (isprint(((char*)mem)[j]))
                    fputc(0xFF & ((char*)mem)[j], stderr);
                else
                    fputc('.', stderr);
            }
            fputc('\n', stderr);
        }
    }
}

#define HEXDUMPDW_COLS 4
void hexdumpdw(void *mem, unsigned int len, int indent) {
    for (unsigned int i = 0; i < len + ((len % HEXDUMPDW_COLS) ? (HEXDUMPDW_COLS - len % HEXDUMPDW_COLS) : 0); i++) {
        if (i % HEXDUMPDW_COLS == 0)
            fprintf(stderr, "%*dx%06x: ", indent*2+1, 0, i*4);

        if (i < len)
            fprintf(stderr, "%08x ", ((unsigned int*)mem)[i]);
        else
            fprintf(stderr, "         ");

        if (i % HEXDUMPDW_COLS == (HEXDUMPDW_COLS - 1))
            fputc('\n', stderr);
    }
}

std::size_t get_nvdec_codec_setup_size(int codec_id) {
    switch (codec_id) {
        case NVC7B0_SET_CONTROL_PARAMS_CODEC_TYPE_MPEG1: return sizeof(nvdec_mpeg2_pic_s);
        case NVC7B0_SET_CONTROL_PARAMS_CODEC_TYPE_MPEG2: return sizeof(nvdec_mpeg2_pic_s);
        case NVC7B0_SET_CONTROL_PARAMS_CODEC_TYPE_MPEG4: return sizeof(nvdec_mpeg4_pic_s);
        case NVC7B0_SET_CONTROL_PARAMS_CODEC_TYPE_VC1:   return sizeof(nvdec_vc1_pic_s);
        case NVC7B0_SET_CONTROL_PARAMS_CODEC_TYPE_H264:  return sizeof(nvdec_h264_pic_s);
        case NVC7B0_SET_CONTROL_PARAMS_CODEC_TYPE_HEVC:  return sizeof(nvdec_hevc_pic_s);
        case NVC7B0_SET_CONTROL_PARAMS_CODEC_TYPE_VP8:   return sizeof(nvdec_vp8_pic_s);
        case NVC7B0_SET_CONTROL_PARAMS_CODEC_TYPE_VP9:   return sizeof(nvdec_vp9_pic_s);
        case NVC7B0_SET_CONTROL_PARAMS_CODEC_TYPE_AV1:   return sizeof(nvdec_av1_pic_s);
        default:                                         return 0;
    }
}

int cs_to_uc(x86_reg reg) {
    switch (reg) {
        default:
            std::fprintf(stderr, "Unhandled register %d (%s)\n", reg, cs_reg_name(capstonehdl, reg));
            return REG_ERR;
        case X86_REG_R8B:
        case X86_REG_R8W:
        case X86_REG_R8D:
        case X86_REG_R8:
            return REG_R8;
        case X86_REG_R9B:
        case X86_REG_R9W:
        case X86_REG_R9D:
        case X86_REG_R9:
            return REG_R9;
        case X86_REG_R10B:
        case X86_REG_R10W:
        case X86_REG_R10D:
        case X86_REG_R10:
            return REG_R10;
        case X86_REG_R11B:
        case X86_REG_R11W:
        case X86_REG_R11D:
        case X86_REG_R11:
            return REG_R11;
        case X86_REG_R12B:
        case X86_REG_R12W:
        case X86_REG_R12D:
        case X86_REG_R12:
            return REG_R12;
        case X86_REG_R13B:
        case X86_REG_R13W:
        case X86_REG_R13D:
        case X86_REG_R13:
            return REG_R13;
        case X86_REG_R14B:
        case X86_REG_R14W:
        case X86_REG_R14D:
        case X86_REG_R14:
            return REG_R14;
        case X86_REG_R15B:
        case X86_REG_R15W:
        case X86_REG_R15D:
        case X86_REG_R15:
            return REG_R15;
        case X86_REG_DIL:
        case X86_REG_DI:
        case X86_REG_EDI:
        case X86_REG_RDI:
            return REG_RDI;
        case X86_REG_SIL:
        case X86_REG_SI:
        case X86_REG_ESI:
        case X86_REG_RSI:
            return REG_RSI;
        case X86_REG_BPL:
        case X86_REG_BP:
        case X86_REG_EBP:
        case X86_REG_RBP:
            return REG_RBP;
        case X86_REG_BL:
        case X86_REG_BX:
        case X86_REG_EBX:
        case X86_REG_RBX:
            return REG_RBX;
        case X86_REG_DL:
        case X86_REG_DX:
        case X86_REG_EDX:
        case X86_REG_RDX:
            return REG_RDX;
        case X86_REG_AL:
        case X86_REG_AX:
        case X86_REG_EAX:
        case X86_REG_RAX:
            return REG_RAX;
        case X86_REG_CL:
        case X86_REG_CX:
        case X86_REG_ECX:
        case X86_REG_RCX:
            return REG_RCX;
        case X86_REG_SPL:
        case X86_REG_SP:
        case X86_REG_ESP:
        case X86_REG_RSP:
            return REG_RSP;
        case X86_REG_IP:
        case X86_REG_EIP:
        case X86_REG_RIP:
            return REG_RIP;
    }
};
