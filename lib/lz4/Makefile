# SPDX-License-Identifier: GPL-2.0-only
ccflags-y += -O3 \
    -DLZ4_FREESTANDING=1 \
    -DLZ4_FAST_DEC_LOOP=1

obj-$(CONFIG_LZ4_COMPRESS) += lz4.o
obj-$(CONFIG_LZ4HC_COMPRESS) += lz4hc.o

obj-$(CONFIG_ARM64) += $(addprefix lz4armv8/, lz4accel.o lz4armv8.o)
