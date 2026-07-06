/* cuInit probe — build: gcc cudacheck.c -I/usr/local/cuda-12.9/include -L/usr/lib/x86_64-linux-gnu -lcuda -o cudacheck */
#include <stdio.h>
#include <cuda.h>
int main(void){
  CUresult r = cuInit(0); const char *s=0; cuGetErrorString(r,&s);
  printf("cuInit(0)        -> %d (%s)\n",(int)r,s?s:"?");
  if(r) return (int)r;
  int n=-1; r=cuDeviceGetCount(&n); cuGetErrorString(r,&s);
  printf("cuDeviceGetCount -> %d (%s), count=%d\n",(int)r,s?s:"?",n);
  return 0;
}
