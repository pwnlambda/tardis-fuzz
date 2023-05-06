# Tardis

Tardis is a hypervisor based snapshot fuzzer for ARMv8 CPUs. Tardis lets you easily run, snapshot and rollback Linux VMs.
It currently only works on CPUs with GICv3 and has only been tested on M1 CPUs on Asahi Linux.

tardis-cli -b 0x403A74 -- bash -c "echo hi" > /dev/null