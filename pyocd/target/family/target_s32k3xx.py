# pyOCD debugger
# Copyright (c) 2020 NXP
# Copyright (c) 2006-2018 Arm Limited
# Copyright (c) 2021 Chris Reed
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
from time import sleep

from ...coresight import ap
from ...coresight import (cortex_m, cortex_m_v8m)
from ...core import exceptions
from ...core.target import Target
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

MDM_IDR_EXPECTED = 0x001c0000
MDM_IDR_VERSION_MASK = 0xf0
MDM_IDR_VERSION_SHIFT = 4

HALT_TIMEOUT = 2.0

class S32K3XX(CoreSightTarget):
    """@brief Family class for NXP S32K3xx devices.
    """

    VENDOR = "NXP"

    def __init__(self, session, memory_map=None):
        super(S32K3XX, self).__init__(session, memory_map)
        self.mdm_ap = None
        self._force_halt_on_connect = False

    def create_init_sequence(self):
        seq = super(S32K3XX, self).create_init_sequence()

        seq.wrap_task('discovery',  lambda seq: seq

            # Cores are not in order in DAP, so we need to number them manually
            .replace_task('create_cores', self.create_s32k3_cores)

            .insert_before('find_components',
                ('check_mdm_ap_idr', self.check_mdm_ap_idr),
                ('check_sda_ap_idr', self.check_sda_ap_idr),
                ('enable_debug', self.enable_s32k3_debug))
        )

        return seq

    def create_s32k3_cores(self):
        # we need to manually adjust the order here as the cores are not in order on the debug interface
        LOG.debug("All Found APs: {}".format(self.dp.aps))

        # Order of core APs in the debug port. Filter all APS discovered with this list
        # note that on the smaller S32K3 devices, not all of these will be available.
        core_aps = [4, 5, 3, 8]

        # Filter with the actually found aps
        core_aps = filter(lambda x: x in self.dp.aps.keys(), core_aps)
        core_aps = [self.dp.aps.get(x) for x in core_aps]

        LOG.debug("Core APs: {}".format(core_aps))
        rom_table_aps = [x for x in core_aps if x.rom_table]
        LOG.debug("Filtered APs: {}".format(rom_table_aps))
        for ap in rom_table_aps:
            ap.rom_table.for_each(self.create_s32k3_core, lambda c: c.factory in (cortex_m.CortexM.factory, cortex_m_v8m.CortexM_v8M.factory))

    def create_s32k3_core(self, cmpid):
        try:
            LOG.debug("Creating %s component", cmpid.name)
            cmp = cmpid.factory(cmpid.ap, cmpid, cmpid.address)
            cmp.init()
        except exceptions.Error as err:
            LOG.error("Error attempting to create component %s: %s", cmpid.name, err, exec_info=self.session.log_tracebacks)

    def enable_s32k3_debug(self):
        self.sda_ap.write_reg(SDA_AP_DBGENCTRL_ADDR, SDA_AP_DBGENCTRL_EN_ALL)

    def check_mdm_ap_idr(self):
        if not self.dp.aps:
            LOG.debug('Not found valid aps, skip MDM-AP check.')
            return

        self.mdm_ap = self.dp.aps[6]

        # Check MDM-AP ID.
        if (self.mdm_ap.idr & ~MDM_IDR_VERSION_MASK) != MDM_IDR_EXPECTED:
            LOG.error("%s: bad MDM-AP IDR (is 0x%08x)", self.part_number, self.mdm_ap.idr)

        self.mdm_ap_version = (self.mdm_ap.idr & MDM_IDR_VERSION_MASK) >> MDM_IDR_VERSION_SHIFT
        LOG.debug("MDM-AP version %d", self.mdm_ap_version)

    def check_sda_ap_idr(self):
        if not self.dp.aps:
            LOG.debug("No valid aps found, skipping sda_ap check")
            return

        self.sda_ap = self.dp.aps[7]
        if self.sda_ap.idr == SDA_AP_IDR_EXPECTED:
            LOG.debug("Found SDA-AP IDR (0x%08x)", self.sda_ap.idr)
        else:
            LOG.error("%s: bad SDA-AP IDR (is 0x%08x)", self.part_number, self.sda_ap.idr)

    def perform_halt_on_connect(self):
        """This init task runs *after* cores are created."""
        if self.session.options.get('connect_mode') == 'under-reset' or self._force_halt_on_connect:
            if not self.mdm_ap or not self.sda_ap:
                return
            LOG.info("Configuring SDA-AP to halt when coming out of reset")
            # Prevent the target from resetting if it has invalid code
            with Timeout(HALT_TIMEOUT) as to:
                while to.check():
                    self.sda_ap.write_reg(SDAAPRSTCTRL_ADDR, 0)
                    if 0 == self.sda_ap.read_reg(SDAAPRSTCTRL_ADDR) & (SDAAPRSTCTRL_RSTRELTLCM70_MASK
                                                                     | SDAAPRSTCTRL_RSTRELTLCM71_MASK
                                                                     | SDAAPRSTCTRL_RSTRELTLCM72_MASK
                                                                     | SDAAPRSTCTRL_RSTRELTLCM73_MASK):
                        break
                else:
                    raise exceptions.TimeoutError("Timed out attempting to set write SDAAPRSTCTRL")

        else:
            super(S32K3XX, self).perform_halt_on_connect()

    def post_connect(self):
        if self.session.options.get('connect_mode') == 'under-reset' or self._force_halt_on_connect:
            if not self.mdm_ap or not self.sda_ap:
                return


            # We can now deassert reset.
            LOG.info("Deasserting reset post connect")
            self.dp.assert_reset(False)

            # Enable debug
            LOG.info("Current_aps: {}".format(self.aps))
            LOG.info("Current_dp_aps: {}".format(self.dp.aps))
            self.dp.aps[4].write_memory(cortex_m.CortexM.DHCSR, cortex_m.CortexM.DBGKEY | cortex_m.CortexM.C_DEBUGEN | cortex_m.CortexM.C_HALT)
            self.dp.aps[5].write_memory(cortex_m.CortexM.DHCSR, cortex_m.CortexM.DBGKEY | cortex_m.CortexM.C_DEBUGEN | cortex_m.CortexM.C_HALT)

            self.dp.aps[4].write_memory(cortex_m.CortexM.DEMCR, cortex_m.CortexM.DEMCR_VC_CORERESET)
            self.dp.aps[5].write_memory(cortex_m.CortexM.DEMCR, cortex_m.CortexM.DEMCR_VC_CORERESET)

            # self.dp.aps[3].write_memory(cortex_m.CortexM.DHCSR, cortex_m.CortexM.DBGKEY | cortex_m.CortexM.C_DEBUGEN |
            #     cortex_m.CortexM.C_HALT)
            # self.dp.aps[8].write_memory(cortex_m.CortexM.DHCSR, cortex_m.CortexM.DBGKEY | cortex_m.CortexM.C_DEBUGEN |
            #     cortex_m.CortexM.C_HALT)

            # I think debug authorization needs to happen here.

            LOG.debug("Core 0 DHCSR: 0x{:08x}".format(self.dp.aps[4].read_memory(cortex_m.CortexM.DHCSR)))
            LOG.debug("Core 1 DHCSR: 0x{:08x}".format(self.dp.aps[5].read_memory(cortex_m.CortexM.DHCSR)))
            LOG.debug("Core 0 DEMCR: 0x{:08x}".format(self.dp.aps[4].read_memory(cortex_m.CortexM.DEMCR)))
            LOG.debug("Core 1 DEMCR: 0x{:08x}".format(self.dp.aps[5].read_memory(cortex_m.CortexM.DEMCR)))


            # self.sda_ap.write_reg(SDAAPRSTCTRL_ADDR, SDAAPRSTCTRL_RSTRELTLCM70_MASK | SDAAPRSTCTRL_RSTRELTLCM71_MASK |
            #     SDAAPRSTCTRL_RSTRELTLCM72_MASK | SDAAPRSTCTRL_RSTRELTLCM73_MASK)
            LOG.debug("Allow core to come out of reaset")
            self.sda_ap.write_reg(SDAAPRSTCTRL_ADDR, SDAAPRSTCTRL_RSTRELTLCM70_MASK)

            if self.get_state() == Target.State.RUNNING:
                raise exceptions.DebugError("Target failed to stay halted during init sequence")

            #
            # # Disable holding the core in reset, leave MDM halt on
            # self.mdm_ap.write_reg(MDM_CTRL, MDM_CTRL_DEBUG_REQUEST)
            #
            # # Wait until the target is halted
            # with Timeout(HALT_TIMEOUT) as to:
            #     while to.check():
            #         if self.mdm_ap.read_reg(MDM_STATUS) & MDM_STATUS_CORE_HALTED == MDM_STATUS_CORE_HALTED:
            #             break
            #         LOG.debug("Waiting for mdm halt")
            #         sleep(0.01)
            #     else:
            #         raise exceptions.TimeoutError("Timed out waiting for core to halt")
            #
            # # release MDM halt once it has taken effect in the DHCSR
            # self.mdm_ap.write_reg(MDM_CTRL, 0)
            #
            # # sanity check that the target is still halted
            # if self.get_state() == Target.State.RUNNING:
            #     raise exceptions.DebugError("Target failed to stay halted during init sequence")
