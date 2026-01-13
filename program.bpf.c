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
};

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(cuda_mytracer, events, event);

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

  u64 blockZ = 0;

  bpf_probe_read_user(&blockZ, sizeof(blockZ), (void *)(PT_REGS_SP(ctx) + 8));

  event->grid_x = gridX;
  event->grid_y = gridY;
  event->grid_z = gridZ;
  event->block_x = blockX;
  event->block_y = blockY;
  event->block_z = blockZ;

  gadget_get_user_stack(ctx,&event->ustack);

  gadget_submit_buf(ctx, &events, event, sizeof(*event));

  return 0;
}

/*SEC("uprobe//usr/local/cuda-13.0/targets/x86_64-linux/lib/libcudart.so.13:__cudaLaunchKernel")*/
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
/**/
/*  gadget_submit_buf(ctx, &events, event, sizeof(*event));*/
/**/
/*  return 0;*/
/**/
/*}*/

/*SEC("tracepoint/syscalls/sys_enter_chdir")*/
/*int tracepoint__sys_enter_chdir(struct trace_event_raw_sys_enter *ctx) {*/
/*  struct event *event;*/
/*  __u64 pid_tgid = bpf_get_current_pid_tgid();*/
/**/
/*  event = gadget_reserve_buf(&events, sizeof(*event));*/
/*  if (!event)*/
/*    return 0;*/
/**/
/*  event->timestamp = bpf_ktime_get_boot_ns();*/
/*  event->mntns_id = gadget_get_current_mntns_id();*/
/*  event->pid = pid_tgid >> 32;*/
/*  bpf_get_current_comm(&event->comm, sizeof(event->comm));*/
/**/
/*  gadget_submit_buf(ctx, &events, event, sizeof(*event));*/
/**/
/*  return 0;*/
/*}*/

char LICENSE[] SEC("license") = "GPL";
