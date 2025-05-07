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

FLASH_ALGO = {
    'load_address' : 0x20000000,

    # Flash algorithm as a hex string
    'instructions': [
    0xe7fdbe00,
    0x46024b09, 0xb5102100, 0x3003f859, 0xb1287a18, 0x4294681c, 0x685cd802, 0xd2044294, 0x330c3103,
    0xd1f3290c, 0xbd102000, 0x000000ac, 0x22304b18, 0xb5702100, 0x4003f859, 0xf0004620, 0x4b11fb03,
    0x07db6a9b, 0x4620d51b, 0x4c0f2300, 0x050cf242, 0xeb042601, 0x01591243, 0x2a005952, 0x4a0bda0c,
    0x440a300c, 0x68526811, 0x011ff021, 0x6c04f800, 0x2c08f840, 0x1c0cf840, 0x2b103301, 0x2000d1e9,
    0xbf00bd70, 0x4039c000, 0x40278000, 0x4027a000, 0x000000ac, 0x47702000, 0x4604b510, 0xffb0f7ff,
    0x4620b9a8, 0xf8fdf000, 0xf9d6f000, 0x2001b108, 0x4620bd10, 0xf82df000, 0xd1f82800, 0xf0004620,
    0xf000f8f0, 0x3800fa43, 0x2001bf18, 0x2000e7f0, 0xb570e7ee, 0x460d4604, 0xf7ff4616, 0xb108ff91,
    0xbd702001, 0xf0004620, 0xf000f8dc, 0x2800f9b5, 0x4632d1f6, 0x46204629, 0xf8aef000, 0xd1ef2800,
    0xf0004620, 0xf000f8ce, 0x3800fa21, 0x2001bf18, 0xb570e7e7, 0xf0004606, 0x4605f8be, 0x4630bb48,
    0xf98ef000, 0xbb204605, 0xf0004630, 0x4604fa87, 0xf0004630, 0xf04ffa7f, 0xf8c033ff, 0xf8c46300,
    0x68233100, 0x0330f023, 0x0310f043, 0x68236023, 0x0301f043, 0x68636023, 0xd5fc041a, 0x045b6863,
    0x6823d509, 0x0301f023, 0x68236023, 0x0330f023, 0x46286023, 0x2504bd70, 0xe92de7fb, 0x460741f0,
    0x4690460c, 0xf890f000, 0x28004605, 0x4638d155, 0xf956f000, 0x28004605, 0xf007d14f, 0x4423031f,
    0xd8552b80, 0xf0001938, 0x4605f94b, 0xd1442800, 0xf0004638, 0x4606fa43, 0xf0004638, 0xeb08fa3b,
    0xf8c00104, 0x46437300, 0x1f08462a, 0xd9374283, 0x0203f1a8, 0x429a1ecb, 0x0394ea4f, 0x0403f024,
    0x2400bf8a, 0x27002701, 0x0208eb04, 0xd90e4291, 0x30fff04f, 0x32014614, 0x42917824, 0x2000ea44,
    0x2f00d1f8, 0x2300bf08, 0xf8463340, 0x68330023, 0x7380f443, 0x68336033, 0x0301f043, 0x68736033,
    0xd5fc041a, 0x045b6873, 0x6833d514, 0x0301f023, 0x68336033, 0x7380f423, 0x46286033, 0x81f0e8bd,
    0x0740f102, 0xcb04f853, 0xf8463201, 0xe7bdc027, 0xe7f22507, 0xe7f02504, 0x41f0e92d, 0x460e4605,
    0x18574690, 0xd30245b8, 0xe8bd2000, 0xf02581f0, 0x19ab041f, 0x46284642, 0x2b7f1b1b, 0x1b64bf8a,
    0x34804634, 0xf7ff4621, 0x2800ff78, 0x4425d1ed, 0x44a01b36, 0xf3c0e7e6, 0x3800000c, 0x2001bf18,
    0xf36f4770, 0x4770000c, 0x001ff010, 0x2001bf18, 0x00004770, 0x447b4b48, 0xe92d681a, 0x2a0041f0,
    0x4b44d165, 0x49454694, 0x1e00f44f, 0x689e6898, 0x689d4479, 0x689c0f40, 0x5642f3c6, 0x3581f3c5,
    0xf3c44613, 0x055f1481, 0xf1014298, 0xf507010c, 0xd14f0780, 0x483a1c99, 0x0f00f1bc, 0x070cf04f,
    0x5141ea4f, 0xbf184478, 0xeb06461a, 0xfb070e03, 0xf04f0003, 0x460f0c00, 0x1880f44f, 0xf100459e,
    0xd13f000c, 0x5106eb01, 0x0f00f1bc, 0x4432d000, 0x260c482c, 0x4cc5eb01, 0x44782700, 0x2e00f44f,
    0x0003fb06, 0x4561461e, 0x000cf100, 0x1c6ed134, 0x442b441e, 0x442ab107, 0x210c4823, 0x5580f04f,
    0x3700f44f, 0xfb014478, 0xbb740003, 0xfb01481f, 0x3202f306, 0x46014478, 0x54ce4418, 0x5300f44f,
    0x51d8f04f, 0x1301e9c0, 0x447b4b19, 0x2000601a, 0x81f0e8bd, 0x3c0cf801, 0x0c01f04f, 0xe9413301,
    0xe7a07e02, 0x3c0cf800, 0x0c01f04f, 0xe9403301, 0xf5077802, 0xe7b11780, 0x6c0cf800, 0x36012701,
    0x1e02e940, 0x2100f501, 0x3c01e7bd, 0xe9c07003, 0xe7ca5701, 0x402ec000, 0x000004ce, 0x0000043c,
    0x00000408, 0x000003d2, 0x000003a8, 0x00000398, 0x000003fa, 0x4604b5f8, 0xf7ff460e, 0xb9b8ff5b,
    0x46054b0d, 0xc034f8df, 0x0e0cf04f, 0x44fc447b, 0xb2eb6819, 0xd8014299, 0xe0092003, 0xc303fb0e,
    0x4294685a, 0x689fd305, 0x4294443a, 0x6033d201, 0x3501bdf8, 0xbf00e7ed, 0x00000378, 0x000002fe,
    0x4604b513, 0xff36f7ff, 0xa901b918, 0xf7ff4620, 0xb002ffd1, 0x0000bd10, 0x4606b573, 0xff1bf7ff,
    0x28004604, 0xa901d141, 0xf7ff4630, 0x4604ffc3, 0xd13a2800, 0x46309b01, 0xf7ff685d, 0x9b01ff12,
    0x5fd8f1b0, 0x0505eba6, 0xd113689a, 0x2280f5c2, 0x20014b2d, 0xf8d3442a, 0x0b521358, 0xea214090,
    0xf8c30100, 0xf8d31358, 0x40d44358, 0x0401f004, 0xe01a00e4, 0xf5b2781b, 0xea4f2f80, 0xd8170383,
    0x4380f103, 0x21010b6d, 0x131af503, 0xf8d340a9, 0xea222340, 0xf8c30201, 0xf8d32340, 0xfa233340,
    0xf015f505, 0xd0000f01, 0x46202409, 0xbd70b002, 0x2180f5a2, 0xd91042a9, 0x4380f103, 0x21010c2d,
    0x131af503, 0xf8d340a9, 0xea22235c, 0xf8c30201, 0xf8d3235c, 0x40ec435c, 0xf5c2e7c8, 0xf1032280,
    0x20014380, 0xf503442a, 0x0b52131a, 0x1340f8d3, 0xea214090, 0xf8c30100, 0xf8d31340, 0x40d33340,
    0x0f01f013, 0xbf00e7cf, 0x40268000, 0x4606b573, 0xfea1f7ff, 0xbb204604, 0x4630a901, 0xff4af7ff,
    0xb9f04604, 0x46309b01, 0xf7ff685d, 0x9b01fe9a, 0x5fd8f1b0, 0x0505eba6, 0xd115689a, 0x2280f5c2,
    0x2301492b, 0xf8d1442a, 0x0b520358, 0x43034093, 0x3358f8c1, 0x4358f8d1, 0x43e440d4, 0x0401f004,
    0x462000e4, 0xbd70b002, 0xf5b2781b, 0xea4f2f80, 0xd8140383, 0x4380f103, 0x22010b6d, 0x131af503,
    0xf8d340aa, 0x430a1340, 0x2340f8c3, 0x3340f8d3, 0xf505fa23, 0x0f01f015, 0x2409d1e3, 0xf5a2e7e1,
    0x42a92180, 0xf103d90e, 0x0c2d4380, 0xf5032201, 0x40aa131a, 0x135cf8d3, 0xf8c3430a, 0xf8d3235c,
    0xe7e5335c, 0x2280f5c2, 0x4380f103, 0x442a2101, 0x131af503, 0xf8d30b52, 0x40910340, 0xf8c34301,
    0xf8d31340, 0x40d33340, 0x0f01f013, 0xbf00e7d4, 0x40268000, 0x47704800, 0x40268000, 0x47704800,
    0x402ec000, 0xb5300783, 0x1884d046, 0xe0044684, 0x1b01f803, 0xd004079d, 0x45a4469c, 0xd1f74663,
    0x3a01bd30, 0xeba24402, 0x2a03020c, 0xb2ccd929, 0x2404eb04, 0xeb042a0f, 0xd92f4404, 0x0c10f1a2,
    0x0c0ff02c, 0x0510f103, 0xe9c344ac, 0xe9c34400, 0x33104402, 0xd1f84563, 0x0f0cf012, 0x0e0ff002,
    0xf02ed018, 0x449c0c03, 0x0504f1ae, 0xf842461a, 0x45624b04, 0xf025d1fb, 0x33040403, 0x0203f00e,
    0x2a004423, 0xb2c9d0cc, 0xf803441a, 0x42931b01, 0xbd30d1fb, 0xe7f44672, 0xe7c64603, 0xe7e04696,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x000006e0, 0x00000000, 0x00000000, 0x00000000, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000031,
    'pc_unInit': 0x20000099,
    'pc_program_page': 0x200000d7,
    'pc_erase_sector': 0x2000009d,
    'pc_eraseAll': 0x120000003,

    'static_base' : 0x20000000 + 0x00000004 + 0x000006e0,
    'begin_stack' : 0x200018b0,
    'end_stack' : 0x200008b0,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x80,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    # Enable double buffering
    'page_buffers' : [
        0x200007b0,
        0x20000830
    ],
    'min_program_length' : 0x80,

    # Relative region addresses and sizes
    'ro_start': 0x4,
    'ro_size': 0x6e0,
    'rw_start': 0x6e4,
    'rw_size': 0xc0,
    'zi_start': 0x7a4,
    'zi_size': 0x0,

    # Flash information
    'flash_start': 0x400000,
    'flash_size': 0x80000,
    'sector_sizes': (
        (0x0, 0x2000),
    )
}

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
