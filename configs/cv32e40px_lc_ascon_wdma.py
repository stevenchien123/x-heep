# Copyright 2026 EPFL
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
#
# Description: CV32E40PX configuration for the DMA-fed, loosely-coupled Ascon
# accelerator instantiated in the simulation testharness.

from xheep import XHeep
from address_map.address_map import AddressMap
from address_map.address_region import AddressRegion
from cpu.cv32e40px import cv32e40px
from bus_type import BusType
from debug_ss.debug_ss import DebugSS
from memory_ss.memory_ss import MemorySS
from memory_ss.linker_section import LinkerSection
from peripherals.base_peripherals import (
    SOC_ctrl,
    Bootrom,
    SPI_flash,
    DMA,
    Power_manager,
    RV_timer_ao,
    Fast_intr_ctrl,
    Ext_peripheral,
    Pad_control,
    GPIO_ao,
)
from peripherals.base_peripherals_domain import BasePeripheralDomain
from peripherals.user_peripherals_domain import UserPeripheralDomain
from peripherals.user_peripherals import RV_plic, UART
from linker_script.linker_script import LinkerScript


def config():
    system = XHeep(BusType.NtoM)
    system.set_cpu(cv32e40px())

    memory_ss = MemorySS()
    memory_ss.add_ram_banks([32] * 2)
    memory_ss.add_ram_banks_il(4, 16, "data_interleaved")
    memory_ss.add_linker_section(LinkerSection.by_size("code", 0, 0x000008000))
    memory_ss.add_linker_section(LinkerSection("data", 0x000008000, None))
    system.set_memory_ss(memory_ss)

    system.set_linker_script_config(LinkerScript(stack_size=0x800, heap_size=0x800))
    system.set_debug_ss(DebugSS(has_spi_slave=1))

    address_map = AddressMap()
    address_map.add_region(
        AddressRegion("debug", start_address=0x10000000, length=0x00100000)
    )
    address_map.add_region(
        AddressRegion(
            "base_peripheral_domain", start_address=0x20000000, length=0x00100000
        )
    )
    address_map.add_region(
        AddressRegion(
            "user_peripheral_domain", start_address=0x30000000, length=0x00100000
        )
    )
    address_map.add_region(
        AddressRegion("flash_mem", start_address=0x40000000, length=0x01000000)
    )
    address_map.add_region(
        AddressRegion("serial_link", start_address=0x50000000, length=0x01000000)
    )
    address_map.add_region(
        AddressRegion("ext_slaves", start_address=0xF0000000, length=0x01000000)
    )
    system.set_address_map(address_map)

    base_peripheral_domain = BasePeripheralDomain()
    user_peripheral_domain = UserPeripheralDomain()

    base_peripheral_domain.add_peripheral(SOC_ctrl(0x00000000))
    base_peripheral_domain.add_peripheral(Bootrom(0x00010000))
    base_peripheral_domain.add_peripheral(SPI_flash(0x00020000, 0x00008000))
    base_peripheral_domain.add_peripheral(
        DMA(
            address=0x30000,
            length=0x10000,
            num_channels=4,
            num_master_ports=2,
            num_channels_per_master_port=2,
        )
    )
    base_peripheral_domain.add_peripheral(Power_manager(0x00040000))
    base_peripheral_domain.add_peripheral(RV_timer_ao(0x00050000))
    base_peripheral_domain.add_peripheral(Fast_intr_ctrl(0x00060000))
    base_peripheral_domain.add_peripheral(Ext_peripheral(0x00070000))
    base_peripheral_domain.add_peripheral(Pad_control(0x00080000))
    base_peripheral_domain.add_peripheral(GPIO_ao(0x00090000))

    user_peripheral_domain.add_peripheral(RV_plic(0x00000000))
    user_peripheral_domain.add_peripheral(UART(0x00080000))

    system.add_peripheral_domain(base_peripheral_domain)
    system.add_peripheral_domain(user_peripheral_domain)

    # Enable the DMA-fed, memory-mapped Ascon accelerator. The CV-X-IF
    # coprocessors remain disabled in this configuration.
    system.add_extension(
        "testharness",
        {
            "FPU_SS_ZFINX": 0,
            "QUADRILATERO": 0,
            "SIMPLE_XIF_COPROC": 0,
            "ASCON_COPROC": 0,
            "ASCON_ACCELERATOR": 1,
            "ASCON_ACCELERATOR_WDMA": 1,
        },
    )

    return system
