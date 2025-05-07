# pyOCD debugger
# Copyright (c) 2023 NXP
# Copyright (c) 2025 Bryan Brauchler
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ..family.target_s32k3xx import (S32K3XX, FLASH_ALGO)
from ...core.memory_map import (FlashRegion, RamRegion, MemoryMap)

class S32K394(S32K3XX):

    VENDOR = "NXP"

    MEMORY_MAP = MemoryMap(
        FlashRegion(name="pflash",  start=0x00400000, end=0x7fffff, blocksize=0x2000, page_size=FLASH_ALGO.get('page_size'), is_boot_memory=True, algo=FLASH_ALGO),
        FlashRegion(name="dflash",  start=0x10000000, end=0x1001ffff, blocksize=0x2000, page_size=FLASH_ALGO.get('page_size'), algo=FLASH_ALGO),
        RamRegion(name="itcm",      start=0x00000000, length=0x8000), # 32 KB
        RamRegion(name="dtcm",      start=0x20000000, length=0x10000), # 64 KB
        RamRegion(name="sram",      start=0x20400000, length=0x80000), # 512 KB
        )

    def __init__(self, session):
        super(S32K394, self).__init__(session, self.MEMORY_MAP)

    @property
    def core_ap_idx_array(self) -> list:
        return [S32K3XX.CM7_0_AHB_AP_IDX, S32K3XX.CM7_1_AHB_AP_IDX, S32K3XX.CM7_2_AHB_AP_IDX]

    def reset(self, reset_type=None):
        super(S32K394, self).reset(self.ResetType.SW_VECTRESET)

    def reset_and_halt(self, reset_type=None, map_to_user=True):
        super(S32K394, self).reset_and_halt(self.ResetType.SW_VECTRESET)

    def create_init_sequence(self):
        seq = super(S32K394, self).create_init_sequence()

        return seq
