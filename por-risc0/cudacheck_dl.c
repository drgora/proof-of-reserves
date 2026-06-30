/* toolkit-free cuInit probe: gcc cudacheck_dl.c -ldl -o cudacheck_dl
   works on host OR chroot — dlopens libcuda.so.1 at runtime, no cuda.h needed */
#include <stdio.h>
#include <dlfcn.h>
typedef int (*cuInit_t)(unsigned);
typedef int (*cuGetErr_t)(int, const char**);
typedef int (*cuCount_t)(int*);
int main(void){
  void *h = dlopen("libcuda.so.1", RTLD_NOW);
  if(!h){ printf("dlopen libcuda.so.1 FAILED: %s\n", dlerror()); return 2; }
  cuInit_t cuInit = (cuInit_t)dlsym(h,"cuInit");
  cuGetErr_t cuErr = (cuGetErr_t)dlsym(h,"cuGetErrorString");
  cuCount_t cuCount = (cuCount_t)dlsym(h,"cuDeviceGetCount");
  int r = cuInit(0); const char *s=0; if(cuErr) cuErr(r,&s);
  printf("cuInit(0) -> %d (%s)\n", r, s?s:"?");
  if(!r && cuCount){ int n=-1; cuCount(&n); printf("cuDeviceGetCount -> count=%d\n", n); }
  return r;
}
