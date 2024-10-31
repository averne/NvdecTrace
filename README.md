# NvdecTrace

Tracing tool for NVDEC command and setup buffers on nvidia.ko

## Building

If needed, edit the source to:
- pick a GpFifo revision (define either `GPFIFO_KEPLER` or `GPFIFO_VOLTA`)
- enable logging components (set `SHOULD_LOG_FILES`/`MEM`/`POLL`/`IOCTL`/`GPFIFO`/`NVDEC` to 1)

Run `xmake`, output will be placed in `build`.

## Using

Output is logged to stderr. Example usage for tracing cuvid calls from FFmpeg:
```
LD_PRELOAD=inject ffmpeg -hide_banner -loglevel error -hwaccel nvdec -i <input file> -f null - > ffmpeg.log 2>&1
```
