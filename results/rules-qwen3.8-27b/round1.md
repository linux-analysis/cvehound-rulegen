# round1

### Yield

| stage | CVEs | rows |
| --- | ---: | ---: |
| attempted | 3322 | 84400 |
| >=1 valid rule | 1948 | 10934 |
| >=1 strong rule | 1910 | 9976 |
| accepted (kept) | 1890 | 6174 |

Accepted CVEs: 56.9% of attempted; 6174 rules.
Strong but unanchored (no introducing commit, so no `Fixes:` header — the suite rejects such rules and the oracle never checked them at an introducing state): 0 CVEs dropped.

Distinct reports (rules that star different lines): 4209 — the rest are siblings re-expressing a report with different context; sample one per CVE per epoch in SFT.

### Repair rounds to the kept rule

| round | rules |
| --- | ---: |
| 0 | 2841 |
| 1 | 1709 |
| 2 | 957 |
| 3 | 667 |

### By fix shape

| shape | rules |
| --- | ---: |
| adds | 2341 |
| changes | 1648 |
| refactor | 1939 |
| removes | 246 |

### By year

| year | rules |
| --- | ---: |
| 2014 | 2 |
| 2015 | 14 |
| 2016 | 77 |
| 2017 | 130 |
| 2018 | 66 |
| 2019 | 219 |
| 2020 | 72 |
| 2021 | 1453 |
| 2022 | 4141 |

### By subsystem

| subsystem | rules |
| --- | ---: |
| arch/arm | 42 |
| arch/arm64 | 28 |
| arch/loongarch | 4 |
| arch/mips | 15 |
| arch/powerpc | 54 |
| arch/riscv | 23 |
| arch/s390 | 5 |
| arch/sparc | 4 |
| arch/x86 | 135 |
| arch/xtensa | 4 |
| block | 77 |
| crypto | 24 |
| drivers/acpi | 17 |
| drivers/android | 1 |
| drivers/ata | 25 |
| drivers/atm | 6 |
| drivers/auxdisplay | 4 |
| drivers/base | 40 |
| drivers/block | 44 |
| drivers/bluetooth | 11 |
| drivers/bus | 28 |
| drivers/char | 40 |
| drivers/clk | 42 |
| drivers/comedi | 7 |
| drivers/cpufreq | 17 |
| drivers/crypto | 75 |
| drivers/cxl | 6 |
| drivers/dax | 4 |
| drivers/dma | 50 |
| drivers/dma-buf | 17 |
| drivers/edac | 4 |
| drivers/firewire | 4 |
| drivers/firmware | 21 |
| drivers/fpga | 8 |
| drivers/gpio | 16 |
| drivers/gpu | 381 |
| drivers/hid | 25 |
| drivers/hsi | 5 |
| drivers/hv | 5 |
| drivers/hwmon | 37 |
| drivers/hwtracing | 22 |
| drivers/i2c | 42 |
| drivers/iio | 57 |
| drivers/infiniband | 135 |
| drivers/input | 36 |
| drivers/interconnect | 4 |
| drivers/iommu | 33 |
| drivers/ipack | 8 |
| drivers/irqchip | 26 |
| drivers/isdn | 21 |
| drivers/leds | 4 |
| drivers/mailbox | 2 |
| drivers/mcb | 4 |
| drivers/md | 47 |
| drivers/media | 169 |
| drivers/memory | 29 |
| drivers/memstick | 8 |
| drivers/mfd | 4 |
| drivers/misc | 54 |
| drivers/mmc | 60 |
| drivers/mtd | 53 |
| drivers/net | 947 |
| drivers/nfc | 32 |
| drivers/nvdimm | 4 |
| drivers/nvme | 45 |
| drivers/nvmem | 7 |
| drivers/of | 6 |
| drivers/parisc | 6 |
| drivers/pci | 39 |
| drivers/peci | 4 |
| drivers/perf | 12 |
| drivers/phy | 12 |
| drivers/pinctrl | 30 |
| drivers/platform | 24 |
| drivers/power | 21 |
| drivers/ptp | 16 |
| drivers/rapidio | 9 |
| drivers/regulator | 12 |
| drivers/remoteproc | 16 |
| drivers/rpmsg | 22 |
| drivers/rtc | 15 |
| drivers/s390 | 14 |
| drivers/scsi | 191 |
| drivers/slimbus | 4 |
| drivers/soc | 44 |
| drivers/soundwire | 2 |
| drivers/spi | 35 |
| drivers/staging | 74 |
| drivers/target | 4 |
| drivers/tee | 6 |
| drivers/thermal | 25 |
| drivers/tty | 38 |
| drivers/uio | 5 |
| drivers/usb | 194 |
| drivers/vdpa | 22 |
| drivers/vfio | 4 |
| drivers/vhost | 11 |
| drivers/video | 49 |
| drivers/virt | 8 |
| drivers/watchdog | 22 |
| drivers/xen | 13 |
| fs | 69 |
| fs/9p | 7 |
| fs/afs | 11 |
| fs/btrfs | 61 |
| fs/cachefiles | 6 |
| fs/ceph | 21 |
| fs/cifs | 45 |
| fs/configfs | 4 |
| fs/crypto | 4 |
| fs/erofs | 12 |
| fs/exfat | 4 |
| fs/ext2 | 4 |
| fs/ext4 | 58 |
| fs/f2fs | 35 |
| fs/fscache | 3 |
| fs/fuse | 8 |
| fs/gfs2 | 2 |
| fs/hfs | 7 |
| fs/hfsplus | 4 |
| fs/hugetlbfs | 2 |
| fs/isofs | 1 |
| fs/jbd2 | 16 |
| fs/jffs2 | 3 |
| fs/jfs | 5 |
| fs/kernfs | 4 |
| fs/ksmbd | 21 |
| fs/lockd | 4 |
| fs/nfs | 47 |
| fs/nfsd | 25 |
| fs/nilfs2 | 12 |
| fs/ntfs | 5 |
| fs/ntfs3 | 34 |
| fs/ocfs2 | 14 |
| fs/orangefs | 4 |
| fs/overlayfs | 19 |
| fs/ubifs | 6 |
| fs/udf | 7 |
| fs/xfs | 4 |
| fs/zonefs | 4 |
| include/acpi | 3 |
| include/linux | 58 |
| include/net | 47 |
| include/sound | 13 |
| include/trace | 3 |
| include/uapi | 5 |
| io_uring | 11 |
| ipc | 11 |
| kernel | 183 |
| lib | 22 |
| mm | 70 |
| net | 4 |
| net/8021q | 4 |
| net/9p | 12 |
| net/bluetooth | 48 |
| net/bpf | 5 |
| net/bridge | 12 |
| net/caif | 12 |
| net/can | 24 |
| net/core | 38 |
| net/dccp | 3 |
| net/dsa | 8 |
| net/ethtool | 5 |
| net/ieee802154 | 1 |
| net/ipv4 | 94 |
| net/ipv6 | 21 |
| net/ipx | 4 |
| net/kcm | 10 |
| net/l2tp | 4 |
| net/llc | 1 |
| net/mac80211 | 17 |
| net/mctp | 16 |
| net/mptcp | 25 |
| net/netfilter | 58 |
| net/nfc | 24 |
| net/openvswitch | 3 |
| net/packet | 4 |
| net/phonet | 4 |
| net/qrtr | 8 |
| net/rds | 17 |
| net/rose | 1 |
| net/rxrpc | 17 |
| net/sched | 54 |
| net/sctp | 6 |
| net/smc | 19 |
| net/sunrpc | 17 |
| net/tipc | 32 |
| net/tls | 2 |
| net/unix | 6 |
| net/wireless | 9 |
| net/x25 | 4 |
| net/xdp | 8 |
| net/xfrm | 8 |
| security | 1 |
| security/apparmor | 4 |
| security/integrity | 16 |
| security/keys | 12 |
| security/selinux | 15 |
| sound/core | 21 |
| sound/drivers | 1 |
| sound/firewire | 4 |
| sound/hda | 4 |
| sound/isa | 12 |
| sound/pci | 4 |
| sound/soc | 129 |
| sound/usb | 21 |
| virt | 16 |

### Context class of the kept rules (RQ4 mix)

| class | rules |
| --- | ---: |
| A | 84 |
| B | 1499 |
| C | 275 |
| C2 | 6 |
| E | 26 |

