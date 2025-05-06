# pyOCD debugger
# Copyright (c) 2020 NXP
# Copyright (c) 2006-2018 Arm Limited
# Copyright (c) 2021 Chris Reed
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

import logging

from ...coresight.ap import (AccessPort, APv1Address)
from ...coresight.cortex_m import CortexM
from ...coresight.core_ids import (CORE_TYPE_NAME, CortexMExtension, CoreArchitecture)
from ...coresight.rom_table import CoreSightComponentID
from ...core import exceptions
from ...coresight.coresight_target import CoreSightTarget
from ...utility.timeout import Timeout

LOG = logging.getLogger(__name__)

SDA_AP_IDR_EXPECTED = 0x001c0040

SDA_AP_DBGENCTRL_CNIDEN_MASK      = 0x20000000
SDA_AP_DBGENCTRL_CNIDEN_SHIFT     = 29
SDA_AP_DBGENCTRL_CDBGEN_MASK      = 0x10000000
SDA_AP_DBGENCTRL_CDBGEN_SHIFT     = 28
SDA_AP_DBGENCTRL_GSPNIDEN_MASK    = 0x80
SDA_AP_DBGENCTRL_GSPNIDEN_SHIFT   = 7
SDA_AP_DBGENCTRL_GSPIDEN_MASK     = 0x40
SDA_AP_DBGENCTRL_GSPIDEN_SHIFT    = 6
SDA_AP_DBGENCTRL_GNIDEN_MASK      = 0x20
SDA_AP_DBGENCTRL_GNIDEN_SHIFT     = 5
SDA_AP_DBGENCTRL_GDBGEN_MASK      = 0x10
SDA_AP_DBGENCTRL_GDBGEN_SHIFT     = 4

SDA_AP_DBGENCTRL_ADDR   = 0x80
SDA_AP_DBGENCTRL_EN_ALL = (SDA_AP_DBGENCTRL_CNIDEN_MASK | SDA_AP_DBGENCTRL_CDBGEN_MASK | SDA_AP_DBGENCTRL_GSPNIDEN_MASK |
                           SDA_AP_DBGENCTRL_GSPIDEN_MASK | SDA_AP_DBGENCTRL_GNIDEN_MASK | SDA_AP_DBGENCTRL_GDBGEN_MASK)

SDAAPRSTCTRL_ADDR               = 0x90
SDAAPRSTCTRL_RSTRELTLCM73_MASK  = 0x10000000
SDAAPRSTCTRL_RSTRELTLCM72_MASK  = 0x08000000
SDAAPRSTCTRL_RSTRELTLCM71_MASK  = 0x04000000
SDAAPRSTCTRL_RSTRELTLCM70_MASK  = 0x02000000
SDAAPRSTCTRL_RSTRELTLCM7_ALL_MASK  = SDAAPRSTCTRL_RSTRELTLCM70_MASK | SDAAPRSTCTRL_RSTRELTLCM71_MASK | SDAAPRSTCTRL_RSTRELTLCM72_MASK | SDAAPRSTCTRL_RSTRELTLCM73_MASK

MDM_IDR_EXPECTED = 0x001c0000
MDM_IDR_VERSION_MASK = 0xf0
MDM_IDR_VERSION_SHIFT = 4

HALT_TIMEOUT = 2.0

class S32K3XX(CoreSightTarget):
    """@brief Family class for NXP S32K3xx devices.
    """

    VENDOR = "NXP"

    CORE_MAPPING = {
    # AP |  Core Number
        4:  0,
        5:  1,
        3:  2,
        8:  3,
    }

    ABP_AP_IDX = 1
    CM7_0_AHB_AP_IDX = 4
    CM7_1_AHB_AP_IDX = 5
    CM7_2_AHB_AP_IDX = 3
    CM7_3_AHB_AP_IDX = 8
    MDM_AP_IDX = 6
    SDA_AP_IDX = 7

    CORE_MAPPING = {
    # AP |  Core Number
        CM7_0_AHB_AP_IDX:  0,
        CM7_1_AHB_AP_IDX:  1,
        CM7_2_AHB_AP_IDX:  2,
        CM7_3_AHB_AP_IDX:  3,
    }


    def __init__(self, session, memory_map=None):
        super(S32K3XX, self).__init__(session, memory_map)
        self.mdm_ap = None
        self.sda_ap = None
        self._force_halt_on_connect = False

    def create_init_sequence(self):
        seq = super(S32K3XX, self).create_init_sequence()

        seq.insert_before('unlock_device',
                        ('s32k3_pre_unlock', self.s32k3_pre_unlock))

        seq.insert_after('unlock_device',
                        ('s32k3_post_unlock', self.s32k3_post_unlock))

        seq.wrap_task('discovery',  lambda seq: seq

            .replace_task('find_aps', self.create_s32k344_aps)
            .insert_before('find_components',
                ('check_mdm_ap_idr', self.check_mdm_ap_idr),
                ('check_sda_ap_idr', self.check_sda_ap_idr),
                ('enable_debug', self.enable_s32k3_debug),
            )
            # Cores are not in order in DAP, so we need to number them manually
            .replace_task('create_cores', self.create_s32k3_cores)

        )

        return seq


    @property
    def core_ap_idx_array(self) -> list:
        return [S32K3XX.CM7_0_AHB_AP_IDX, S32K3XX.CM7_1_AHB_AP_IDX, S32K3XX.CM7_2_AHB_AP_IDX, S32K3XX.CM7_3_AHB_AP_IDX]

    def create_s32k344_aps(self):
        # reading a reserved AP yields a memory transfer fault. Supply a list of expected
        # aps for the create AP process.
        self.dp.valid_aps = [S32K3XX.ABP_AP_IDX, S32K3XX.MDM_AP_IDX, S32K3XX.SDA_AP_IDX] + self.core_ap_idx_array
        LOG.info("setting valid aps: {}".format(self.dp.valid_aps))

    def _s32k3_sda_ap_assert_reset(self, sda_ap: AccessPort, reset_value: bool = False):
        """@brief assert/deassert all core resets in SDA_AP"""

        value = sda_ap.read_reg(SDAAPRSTCTRL_ADDR)
        if reset_value == False:
            # set core bits to 1
            value = value | SDAAPRSTCTRL_RSTRELTLCM7_ALL_MASK
        else:
            # set core bits to 0
            value = value & ~(SDAAPRSTCTRL_RSTRELTLCM7_ALL_MASK)

        with Timeout(HALT_TIMEOUT) as to:
            while to.check():
                LOG.debug("Allow cores to come out of reset")
                sda_ap.write_reg(SDAAPRSTCTRL_ADDR, value)
                if sda_ap.read_reg(SDAAPRSTCTRL_ADDR) & value == value:
                    break
            else:
                raise exceptions.TimeoutError("Timed out attempting to set write SDAAPRSTCTRL")

    def create_s32k3_cores(self):
        """
        @brief Create all cores found when scanning

        This task creates cores from the scanned APs.

        On S32K3 devices there are 2 challenges:
        1) On some of the larger devices, APs are not in ascending core order, and cores will be added
        in the wrong order when using the default CortexM factory
        2) On devices that configure can Core 0/1 in lockstep, Core 0 AP will act as the debug port for
        the lockstep pair. Core 1's AP is unused and should be skipped when adding cores. This also
        affects core numbering for these devices. This can be configured via OTP so the core configuration
        is not garenteed when connecting to the device.

        For now, we will used a hard-coded core definition from the derivative class, and create multiple
        derivative classes for each core configuration. (S32K388 vs S32K388LS)
        Turns out, the AP will error out during discovery, we may not even have to deal with this.
        """
        # we need to manually adjust the order here as the cores are not in order on the debug interface
        LOG.debug("All Found APs: {}".format(self.dp.aps))

        valid_dict = {k: v for k, v in self.dp.aps.items() if v.has_rom_table}
        LOG.debug("Filtered APs: {}".format(valid_dict))

        for n, ap in {k: v for k, v in self.dp.aps.items() if v.has_rom_table}.items():
            f = lambda cmpid: self._create_s32k3_core(cmpid, S32K3XX.CORE_MAPPING.get(n))
            ap.rom_table.for_each(f, lambda c: c.factory == CortexM.factory)

    def _create_s32k3_core(self, cmpid: CoreSightComponentID, core_number: int):
        try:
            LOG.debug("Creating %s component", cmpid.name)
            core = CortexM7_S32K3(self.session, cmpid.ap, self.memory_map, core_number, cmpid, cmpid.address)

            if cmpid.ap.core is not None:
                raise exceptions.TargetError(f"{cmpid.ap.short_description} has multiple cores associated with it")
            cmpid.ap.core = core

            self.add_core(core)
            core.init()

        except exceptions.Error as err:
            LOG.error("Error attempting to create component %s: %s", cmpid.name, err, exc_info=self.session.log_tracebacks)

    def enable_s32k3_debug(self):
        self.sda_ap.write_reg(SDA_AP_DBGENCTRL_ADDR, SDA_AP_DBGENCTRL_EN_ALL)

    def check_mdm_ap_idr(self):
        if not self.dp.aps:
            LOG.debug('Not found valid aps, skip MDM-AP check.')
            return

        self.mdm_ap = self.dp.aps[S32K3XX.MDM_AP_IDX]

        # Check MDM-AP ID.
        if (self.mdm_ap.idr & ~MDM_IDR_VERSION_MASK) != MDM_IDR_EXPECTED:
            LOG.error("%s: bad MDM-AP IDR (is 0x%08x)", self.part_number, self.mdm_ap.idr)

        self.mdm_ap_version = (self.mdm_ap.idr & MDM_IDR_VERSION_MASK) >> MDM_IDR_VERSION_SHIFT
        LOG.debug("MDM-AP version %d", self.mdm_ap_version)

    def check_sda_ap_idr(self):
        if not self.dp.aps:
            LOG.debug("No valid aps found, skipping sda_ap check")
            return

        self.sda_ap = self.dp.aps[S32K3XX.SDA_AP_IDX]
        self._check_sda_ap_idr(self.sda_ap)

    def _check_sda_ap_idr(self, sda_ap: AccessPort):
        if not sda_ap:
            LOG.debug("No valid ap, skipping sda_ap check")
            return

        if sda_ap.idr == SDA_AP_IDR_EXPECTED:
            LOG.debug("Found SDA-AP IDR (0x%08x)", sda_ap.idr)
        else:
            LOG.error("%s: bad SDA-AP IDR (is 0x%08x)", self.part_number, sda_ap.idr)

    def s32k3_post_unlock(self):
        pass

    def s32k3_pre_unlock(self):

        sda_ap = AccessPort.create(self.dp, APv1Address(S32K3XX.SDA_AP_IDX))

        self._check_sda_ap_idr(sda_ap)

        if self.session.options.get('connect_mode') == 'under-reset' or self._force_halt_on_connect:

            # Note that in order to perform debug unlock, the device has to come out of reset.
            # Therefore, we write registers to keep the cores in reset and de-assert the reset
            # pin now to allow for debug authentication. Cores will be released later.
            self._s32k3_sda_ap_assert_reset(sda_ap, True)

            LOG.debug("Deasserting Reset")
            self.dp.assert_reset(False)

    def perform_halt_on_connect(self):
        """This init task runs *after* cores are created."""
        if self.session.options.get('connect_mode') == 'under-reset' or self._force_halt_on_connect:
            for core in self.cores.values():
                core.ap.write_memory(CortexM.DHCSR, CortexM.DBGKEY | CortexM.C_DEBUGEN | CortexM.C_HALT)
                core.ap.write_memory(CortexM.DEMCR, CortexM.DEMCR_VC_CORERESET)

            self._s32k3_sda_ap_assert_reset(self.sda_ap, False)
        else:
            super(S32K3XX, self).perform_halt_on_connect()


class CortexM7_S32K3(CortexM):

    def _read_core_type(self) -> None:
        """
        @brief Read the CPUID register and determine core type and architecture.

        On S32K3XX, we can read the CPUID register but not ISAR3 or MPU_TYPE
        while the core is in reset. This occurs durring connect under-reset as
        well as when a core is not enabled out of reset (cascade boot).

        Therefore, we will hard code these feature registers so that core can be
        created even when the core is in reset.
        """
        LOG.info("Reading S32K3 core info")
        # Read CPUID register
        cpuid_cb = self.read32(CortexM.CPUID, now=False)

        # Check CPUID
        cpuid = cpuid_cb()
        implementer = (cpuid & CortexM.CPUID_IMPLEMENTER_MASK) >> CortexM.CPUID_IMPLEMENTER_POS
        arch = (cpuid & CortexM.CPUID_ARCHITECTURE_MASK) >> CortexM.CPUID_ARCHITECTURE_POS
        self.core_type = (cpuid & CortexM.CPUID_PARTNO_MASK) >> CortexM.CPUID_PARTNO_POS
        self.cpu_revision = (cpuid & CortexM.CPUID_VARIANT_MASK) >> CortexM.CPUID_VARIANT_POS
        self.cpu_patch = (cpuid & CortexM.CPUID_REVISION_MASK) >> CortexM.CPUID_REVISION_POS

        # Check for DSP extension
        isar3 = 0x1111131
        isar3_simd = (isar3 & self.ISAR3_SIMD_MASK) >> self.ISAR3_SIMD_SHIFT
        if isar3_simd == self.ISAR3_SIMD__DSP:
            self._extensions.append(CortexMExtension.DSP)

        # Check for MPU extension
        mpu_type = 0x1000
        mpu_type_dregions = (mpu_type & self.MPU_TYPE_DREGIONS_MASK) >> self.MPU_TYPE_DREGIONS_SHIFT
        if mpu_type_dregions > 0:
            self._extensions.append(CortexMExtension.MPU)

        # Set the arch version.
        if arch == CortexM.ARMv7M:
            self._architecture = CoreArchitecture.ARMv7M
            self._arch_version = (7, 0)
        else:
            self._architecture = CoreArchitecture.ARMv6M
            self._arch_version = (6, 0)

        self._core_name = CORE_TYPE_NAME.get((implementer, self.core_type), f"Unknown (CPUID={cpuid:#010x})")
