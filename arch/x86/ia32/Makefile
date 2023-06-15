# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the ia32 kernel emulation subsystem.
#

MEMORIZER_INSTRUMENT_ia32_signal.o := n
ifdef CONFIG_MEMORIZER
KASAN_SANITIZE_ia32_signal.o := n
endif

obj-$(CONFIG_IA32_EMULATION) := ia32_signal.o

audit-class-$(CONFIG_AUDIT) := audit.o
obj-$(CONFIG_IA32_EMULATION) += $(audit-class-y)
