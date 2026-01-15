// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 Alejandro Salamanca */

#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/user_stack_map.h>
#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns.h>
#include <gadget/types.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif
#define MAX_GPUKERN_ARGS 16
#define DIR_HTOD 0
#define DIR_DTOH 1
typedef __u64 CUdeviceptr;
typedef __u64 CUstream;

GADGET_PARAM(collect_ustack);

struct event {
  gadget_timestamp timestamp;
  gadget_mntns_id mntns_id;
  gadget_pid pid;
  gadget_comm comm[TASK_COMM_LEN];
  __u32 grid_x;
  __u32 grid_y;
  __u32 grid_z;

  __u32 block_x;
  __u32 block_y;
  __u32 block_z;

  struct gadget_user_stack ustack;
  u64 stream;

};

struct memalloc_event{
  gadget_timestamp timestamp;
  gadget_mntns_id mntns_id;
  gadget_pid pid;
  gadget_comm comm[TASK_COMM_LEN];
  size_t byte_size;
};

struct memcpy_event{
  gadget_timestamp timestamp;
  gadget_mntns_id mntns_id;
  gadget_pid pid;
  gadget_comm comm[TASK_COMM_LEN];
  size_t byte_size;
  u8 kind;
};

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER_MAP(memalloc_events, 1024 * 256);
GADGET_TRACER_MAP(memcpy_events, 1024 * 256);

GADGET_TRACER(cuda_mytracer, events, event);
GADGET_TRACER(memalloc_tracer, memalloc_events, memalloc_event);
GADGET_TRACER(memcpy_tracer, memcpy_events, memcpy_event);

SEC("uprobe/libcuda:cuLaunchKernel")
int BPF_UPROBE(handle_cuLaunchkernel,
    u64 func,
    u64 gridX, u64 gridY, u64 gridZ,
    u64 blockX, u64 blockY){

  bpf_printk("CudaLaunchKernel called");
  struct event *event;

  event = gadget_reserve_buf(&events, sizeof(*event));
  if (!event)
    return 0;

  // process info
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  event->timestamp = bpf_ktime_get_boot_ns();
  event->mntns_id = gadget_get_current_mntns_id();
  event->pid = pid_tgid >> 32;
  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  u64 blockZ = 0,stream=0;

  bpf_probe_read_user(&blockZ, sizeof(blockZ), (void *)(PT_REGS_SP(ctx) + 8));

  bpf_probe_read_user(&stream, sizeof(stream),(void *)(PT_REGS_SP(ctx) + 24));

  event->grid_x = gridX;
  event->grid_y = gridY;
  event->grid_z = gridZ;
  event->block_x = blockX;
  event->block_y = blockY;
  event->block_z = blockZ;
  event->stream = stream;

  gadget_get_user_stack(ctx,&event->ustack);

  gadget_submit_buf(ctx, &events, event, sizeof(*event));

  return 0;
}

static __always_inline
int handle_cuMemAlloc_impl(void **devptr, size_t bytesize, struct pt_regs *ctx)
{
  bpf_printk("CudaMemalloc called");

  struct memalloc_event *event =
      gadget_reserve_buf(&memalloc_events, sizeof(*event));
  if (!event)
    return 0;

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  event->timestamp = bpf_ktime_get_boot_ns();
  event->mntns_id = gadget_get_current_mntns_id();
  event->pid = pid_tgid >> 32;
  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  event->byte_size = bytesize;

  gadget_submit_buf(ctx, &memalloc_events, event, sizeof(*event));
  return 0;
}

SEC("uprobe/libcuda:cuMemAlloc")
int BPF_KPROBE(handle_cuMemAlloc, void **devptr, size_t bytesize){
  return handle_cuMemAlloc_impl(devptr, bytesize, ctx);
}

SEC("uprobe/libcuda:cuMemAlloc_v2")
int BPF_KPROBE(handle_cuMemAlloc_v2, void **devptr, size_t bytesize){
  return handle_cuMemAlloc_impl(devptr, bytesize, ctx);
}

static __always_inline
int handle_cuMemcpy_htod_impl(CUdeviceptr dst, const void *src, size_t bytesize,struct pt_regs *ctx){
  bpf_printk("cuMemcpyHtoD called");

  struct memcpy_event *event;

  event = gadget_reserve_buf(&memcpy_events, sizeof(*event));
  if (!event)
    return 0;

  // process info
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  event->timestamp = bpf_ktime_get_boot_ns();
  event->mntns_id = gadget_get_current_mntns_id();
  event->pid = pid_tgid >> 32;
  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  event->byte_size = bytesize;
  event->kind = DIR_HTOD;

  gadget_submit_buf(ctx,&memcpy_events,event,sizeof(*event));
  return 0;
}


SEC("uprobe/libcuda:cuMemcpyHtoD")
int BPF_KPROBE(handle_cuMemcpy_htod, CUdeviceptr dst, const void *src, size_t bytesize){
  return handle_cuMemcpy_htod_impl(dst,src,bytesize,ctx);
}

SEC("uprobe/libcuda:cuMemcpyHtoD_v2")
int BPF_KPROBE(handle_cuMemcpy_htod_v2, CUdeviceptr dst, const void *src, size_t bytesize){
  return handle_cuMemcpy_htod_impl(dst,src,bytesize,ctx);
}

SEC("uprobe/libcuda:cuMemcpyHtoDAsync_v2")
int BPF_KPROBE(handle_cuMemcpy_htod_async_v2, CUdeviceptr dst, const void *src, size_t bytesize,u64 stream){
  return handle_cuMemcpy_htod_impl(dst,src,bytesize,ctx);
}

SEC("uprobe/libcuda:cuMemcpyHtoDAsync")
int BPF_KPROBE(handle_cuMemcpy_htod_async, CUdeviceptr dst, const void *src, size_t bytesize,u64 stream){
  return handle_cuMemcpy_htod_impl(dst,src,bytesize,ctx);
}

static __always_inline
int handle_cuMemcpy_dtoh_impl(void *dst, CUdeviceptr src, size_t bytesize, struct pt_regs *ctx){
  bpf_printk("cuMemcpyDtoH called");

  struct memcpy_event *event;

  event = gadget_reserve_buf(&memcpy_events, sizeof(*event));
  if (!event)
    return 0;

  // process info
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  event->timestamp = bpf_ktime_get_boot_ns();
  event->mntns_id = gadget_get_current_mntns_id();
  event->pid = pid_tgid >> 32;
  bpf_get_current_comm(&event->comm, sizeof(event->comm));

  event->byte_size = bytesize;
  event->kind = DIR_DTOH;

  gadget_submit_buf(ctx,&memcpy_events,event,sizeof(*event));
  return 0;
}

SEC("uprobe/libcuda:cuMemcpyDtoH")
int BPF_KPROBE(handle_cuMemcpy_dtoh, void *dst, CUdeviceptr src, size_t bytesize){
  return handle_cuMemcpy_dtoh_impl(dst, src, bytesize,ctx);
}

SEC("uprobe/libcuda:cuMemcpyDtoH_v2")
int BPF_KPROBE(handle_cuMemcpy_dtoh_v2, void *dst, CUdeviceptr src, size_t bytesize){
  return handle_cuMemcpy_dtoh_impl(dst, src, bytesize,ctx);
}

SEC("uprobe/libcuda:cuMemcpyDtoHAsync_v2")
int BPF_KPROBE(handle_cuMemcpy_dtoh_async_v2, void *dst, CUdeviceptr src, size_t bytesize, u64 stream){
  return handle_cuMemcpy_dtoh_impl(dst, src, bytesize,ctx);
}

SEC("uprobe/libcuda:cuMemcpyDtoHAsync")
int BPF_KPROBE(handle_cuMemcpy_dtoh_async, void *dst, CUdeviceptr src, size_t bytesize,u64 stream){
  return handle_cuMemcpy_dtoh_impl(dst, src, bytesize,ctx);
}

/*SEC("uprobe/libcudart:cudaLaunchKernel")*/
/*int BPF_UPROBE(handle_cudaLaunchKernel,*/
/*               u64 func,*/
/*               u64 grid_xy,*/
/*               u64 grid_z,*/
/*               u64 block_xy,*/
/*               u64 block_z,*/
/*               uintptr_t argv){*/
/*  struct event *event;*/
/**/
/*  bpf_printk("CudaLaunchKernel called");*/
/*  __u64 pid_tgid = bpf_get_current_pid_tgid();*/
/*  event = gadget_reserve_buf(&events, sizeof(*event));*/
/*  if (!event)*/
/*    return 0;*/
/**/
/*  // process info*/
/*  event->timestamp = bpf_ktime_get_boot_ns();*/
/*  event->mntns_id = gadget_get_current_mntns_id();*/
/*  event->pid = pid_tgid >> 32;*/
/*  bpf_get_current_comm(&event->comm, sizeof(event->comm));*/
/**/
/*  // Launch Kernel info*/
/*  event->block_x = (u32)block_xy;*/
/*  event->block_y = (u32)(block_xy >> 32);*/
/*  event->block_z = (u32)block_z;*/
/*  event->grid_x = (u32)grid_xy;*/
/*  event->grid_y = (u32)(grid_xy >> 32);*/
/*  event->grid_z = (u32)grid_z;*/
/*  u64 stream =0;*/
/*  bpf_probe_read_user(&stream, sizeof(stream),(void *)(PT_REGS_SP(ctx) + 16));*/
/*  event->stream=stream;*/
/*  gadget_get_user_stack(ctx,&event->ustack);*/
/**/
/*  gadget_submit_buf(ctx, &events, event, sizeof(*event));*/
/**/
/*  return 0;*/
/**/
/*}*/

char LICENSE[] SEC("license") = "GPL";
