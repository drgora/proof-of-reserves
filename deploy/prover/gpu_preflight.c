// gpu-preflight: decide whether the CUDA r0vm can actually be used, WITHOUT needing the
// CUDA toolkit at build time or libcudart at runtime. We dlopen the driver (libcuda.so.1,
// injected by `docker run --gpus ...`) and call the CUDA Driver API directly:
//
//   exit 0  -> a CUDA device exists AND has >= <min_gb> GiB free VRAM   (use GPU r0vm)
//   exit 1  -> no usable driver / no device / query failed              (use CPU r0vm)
//   exit 2  -> device present but too little free VRAM                  (use CPU r0vm)
//
// Rationale (measured 2026-07-10): `nvidia-smi` reports a GPU even when CUDA compute is
// unavailable (cuInit -> error 304 in some VMs/chroots) or the card is too small (8 GB OOMs
// the PoR succinct proof, which needs >= 16 GB). So detection MUST exercise the real driver +
// check free VRAM, not just nvidia-smi. dlopen (not linking libcuda) keeps this binary
// runnable on a CPU-only host where libcuda.so.1 is absent -> it cleanly reports "no GPU".
//
// Built with a plain C compiler (cc); no CUDA toolkit needed on the build host.
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

typedef int CUresult;
typedef int CUdevice;
typedef void *CUcontext;

int main(int argc, char **argv) {
    double min_gb = (argc > 1) ? atof(argv[1]) : 16.0;

    void *h = dlopen("libcuda.so.1", RTLD_NOW);
    if (!h) h = dlopen("libcuda.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "gpu-preflight: libcuda.so.1 not present (no NVIDIA driver / no --gpus)\n"); return 1; }

    CUresult (*cuInit)(unsigned) = dlsym(h, "cuInit");
    CUresult (*cuDeviceGetCount)(int *) = dlsym(h, "cuDeviceGetCount");
    CUresult (*cuDeviceGet)(CUdevice *, int) = dlsym(h, "cuDeviceGet");
    CUresult (*cuCtxCreate)(CUcontext *, unsigned, CUdevice) = dlsym(h, "cuCtxCreate_v2");
    CUresult (*cuMemGetInfo)(size_t *, size_t *) = dlsym(h, "cuMemGetInfo_v2");
    CUresult (*cuDeviceGetName)(char *, int, CUdevice) = dlsym(h, "cuDeviceGetName");
    if (!cuInit || !cuDeviceGetCount || !cuDeviceGet || !cuCtxCreate || !cuMemGetInfo) {
        fprintf(stderr, "gpu-preflight: driver API symbols missing\n"); return 1;
    }

    CUresult r = cuInit(0);
    if (r != 0) { fprintf(stderr, "gpu-preflight: cuInit failed (err %d) -> no usable GPU\n", r); return 1; }

    int n = 0;
    if (cuDeviceGetCount(&n) != 0 || n < 1) { fprintf(stderr, "gpu-preflight: no CUDA device\n"); return 1; }

    CUdevice dev; CUcontext ctx;
    if (cuDeviceGet(&dev, 0) != 0 || cuCtxCreate(&ctx, 0, dev) != 0) {
        fprintf(stderr, "gpu-preflight: cannot create context on device 0\n"); return 1;
    }
    size_t freeB = 0, totB = 0;
    if (cuMemGetInfo(&freeB, &totB) != 0) { fprintf(stderr, "gpu-preflight: cuMemGetInfo failed\n"); return 1; }

    char name[256] = "GPU";
    if (cuDeviceGetName) cuDeviceGetName(name, sizeof name, dev);
    double free_gb = freeB / 1073741824.0, tot_gb = totB / 1073741824.0;
    fprintf(stderr, "gpu-preflight: %s — %.1f/%.1f GiB free (need >= %.1f)\n", name, free_gb, tot_gb, min_gb);

    return (free_gb >= min_gb) ? 0 : 2;
}
