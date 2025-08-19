# XDP_AF

Library for speedrunning `AF_XDP` ebpf programs. It handles the boilerplate configuration for making these sort of programs so you only have to implement the logic unique to your specific program.

Shoutout to quilkin for being one of the few rust-based AF_XDP programs in the wild. I spent so much time trying to understand your code I turned it into a library.

## How to use this Crate

- Implement the traits in `xdp_af::traits`.
- pass the userspace_config to the builder.
- tweak the configuration options wrapped by the builder
- build

step 1 is very much a draw the rest of the owl kind of task. Most of the logic is going to be in the batch packet processing function. The ebpf module itself will probably be comparatively easy.

if you see anything missing which you think makes sense to implement for the majority of AF_XDP programs, or have some functionality in mind you think would be beneficial to implementors, feel free to open an issue or PR.
