import shutil
import subprocess
from importlib import resources
from pathlib import Path


class GitHubCompileConfig:
    def __init__(self, git_folder: Path):
        self.ignored_files = [
            "converter-example.c",
            "converter-sample.c",
        ]

        self.additional_ignored_files = {
            "open5gs/open5gs": [
                "oer_encoder.c",
                "oer_decoder.c",
                "jer_encoder.c",
                "jer_decoder.c",
                "_jer.c",
                "_oer.c",
                "xer_encoder.c",
                "xer_decoder.c",
                "ber_encoder.c",
                "ber_decoder.c",
                "der_encoder.c",
            ],
            "vaggelis-sudo/5G-UE-SecurityTesting": [
                "oer_encoder.c",
                "oer_decoder.c",
                "jer_encoder.c",
                "jer_decoder.c",
                "_jer.c",
                "_oer.c",
                "xer_encoder.c",
                "xer_decoder.c",
                "ber_encoder.c",
                "ber_decoder.c",
                "der_encoder.c",
            ],
            "vlm/ldap-server-example": ["ldap-server.c"],
            "ucoruh/asn1c-wsl-sample": ["main.c"],
            "lixiaolong1997/asn1": ["main.c"],
            "joaorufino/go-projects": ["cam_decoder.c"],
            "SyNSec-den/5GBaseChecker": [
                "oer_encoder.c",
                "oer_decoder.c",
                "jer_encoder.c",
                "jer_decoder.c",
                "_jer.c",
                "_oer.c",
                "xer_encoder.c",
                "xer_decoder.c",
                "ber_encoder.c",
                "ber_decoder.c",
                "der_encoder.c",
            ],
            "l4es/IndustrialAutomation": [
                "Copy of asn_codecs_prim.c",
                "Copy of asn_SEQUENCE_OF.c",
                "Copy of asn_SET_OF.c",
            ],
        }

        folder = str(git_folder) + "/"
        self.folder = git_folder

        self.additional_compile_options = {
            "open5gs/open5gs": '-DASN_DISABLE_OER_SUPPORT -I"'
            + folder
            + 'open5gs/open5gs/lib" -I"'
            + folder
            + 'open5gs/open5gs/build/lib" -I"'
            + folder
            + 'open5gs/open5gs/build/lib/core" "'
            + folder
            + 'open5gs/open5gs/lib/core/ogs-log.c" "'
            + folder
            + 'open5gs/open5gs/lib/core/ogs-abort.c" "'
            + folder
            + 'open5gs/open5gs/lib/core/ogs-strings.c" "'
            + folder
            + 'open5gs/open5gs/lib/core/ogs-memory.c" "'
            + folder
            + 'open5gs/open5gs/lib/core/ogs-pkbuf.c" "'
            + folder
            + 'open5gs/open5gs/lib/core/ogs-core.c" "'
            + folder
            + 'open5gs/open5gs/lib/core/ogs-hash.c" "'
            + folder
            + 'open5gs/open5gs/lib/core/ogs-errno.c" "'
            + folder
            + 'open5gs/open5gs/lib/core/ogs-time.c" "'
            + folder
            + 'open5gs/open5gs/lib/core/ogs-socket.c" "'
            + folder
            + 'open5gs/open5gs/lib/core/ogs-tlv.c" "'
            + folder
            + 'open5gs/open5gs/lib/core/ogs-sockaddr.c" -ltalloc',
            # o5gs is too complicated to get working. Revisit at a later time to get working.
            "riebl/vanetza": folder + "riebl/vanetza/vanetza/asn1/memory.c",
            "SatDump/SatDump": '-I"'
            + folder
            + 'SatDump/SatDump/plugins/inmarsat_support" "'
            + folder
            + 'SatDump/SatDump/plugins/inmarsat_support/aero/libacars/vstring.c" "'
            + folder
            + 'SatDump/SatDump/plugins/inmarsat_support/aero/libacars/util.c"',
            "smartgridadsc/IEC61850ToolChain": '-I"'
            + folder
            + 'smartgridadsc/IEC61850ToolChain/config" -I"'
            + folder
            + 'smartgridadsc/IEC61850ToolChain/hal/inc" "'
            + folder
            + 'smartgridadsc/IEC61850ToolChain/hal/memory/lib_memory.c"',
            "riclolsen/json-scada": ' -I"'
            + folder
            + 'riclolsen/json-scada/src/libiec61850/config" -I"'
            + folder
            + 'riclolsen/json-scada/src/libiec61850/src/common/inc" -I"'
            + folder
            + 'riclolsen/json-scada/src/libiec61850/hal/inc" -I"'
            + folder
            + 'riclolsen/json-scada/src/libiec61850/src/mms/inc" "'
            + folder
            + 'riclolsen/json-scada/src/libiec61850/hal/memory/lib_memory.c"',
            "szpajder/dumpvdl2": '-include unistd.h -I"'
            + folder
            + 'szpajder/libacars" "'
            + folder
            + 'szpajder/libacars/libacars/vstring.c" "'
            + folder
            + 'szpajder/libacars/libacars/util.c" "'
            + folder
            + 'szpajder/libacars/libacars/configuration.c" "'
            + folder
            + 'szpajder/libacars/libacars/hash.c" "'
            + folder
            + 'szpajder/libacars/libacars/list.c"',
            "szpajder/libacars": '-include unistd.h "'
            + folder
            + 'szpajder/libacars/libacars/vstring.c" "'
            + folder
            + 'szpajder/libacars/libacars/util.c" "'
            + folder
            + 'szpajder/libacars/libacars/configuration.c" "'
            + folder
            + 'szpajder/libacars/libacars/hash.c" "'
            + folder
            + 'szpajder/libacars/libacars/list.c"',  # Must run cmake once with WITH_JANSSON, WITH_XML
            "privat-it/cryptonite": "-D'CRYPTONITE_EXPORT=extern' -I\""
            + folder
            + 'privat-it/cryptonite/src/cryptonite/c" -I"'
            + folder
            + 'privat-it/cryptonite/src/pthread/c" "'
            + folder
            + 'privat-it/cryptonite/src/pthread/c/pthread_impl.c" "'
            + folder
            + 'privat-it/cryptonite/src/cryptonite/c/byte_array.c" "'
            + folder
            + 'privat-it/cryptonite/src/cryptonite/c/stacktrace.c" "'
            + folder
            + 'privat-it/cryptonite/src/cryptonite/c/byte_utils_internal.c"',
            "hmusavi/asn1_codec": "-DASN_DISABLE_OER_SUPPORT",
            "osmocom/osmo-cbc": ' -DASN_DISABLE_UPER_SUPPORT -DASN_DISABLE_OER_SUPPORT -DASN_DISABLE_BER_SUPPORT -DASN_DISABLE_JER_SUPPORT -DASN_DISABLE_XER_SUPPORT"'
            + folder
            + 'osmocom/osmo-cbc/src/sbcap/sbcap_common.c" -losmocore',  # Test
            "NICMx/FORT-validator": '-D_XOPEN_SOURCE=500 -D_DEFAULT_SOURCE -D__USE_XOPEN_EXTENDED -include time.h -I/usr/include/libxml2/ "'
            + folder
            + 'NICMx/FORT-validator/src/json_util.c" "'
            + folder
            + 'NICMx/FORT-validator/src/libcrypto_util.c" "'
            + folder
            + 'NICMx/FORT-validator/src/log.c" "'
            + folder
            + 'NICMx/FORT-validator/src/config/uint.c" "'
            + folder
            + 'NICMx/FORT-validator/src/config/str.c" "'
            + folder
            + 'NICMx/FORT-validator/src/config/boolean.c" "'
            + folder
            + 'NICMx/FORT-validator/src/config/mode.c" "'
            + folder
            + 'NICMx/FORT-validator/src/alloc.c" "'
            + folder
            + 'NICMx/FORT-validator/src/config/file_type.c" "'
            + folder
            + 'NICMx/FORT-validator/src/config/output_format.c" "'
            + folder
            + 'NICMx/FORT-validator/src/config/incidences.c" "'
            + folder
            + 'NICMx/FORT-validator/src/config/filename_format.c" "'
            + folder
            + 'NICMx/FORT-validator/src/config/log_conf.c" "'
            + folder
            + 'NICMx/FORT-validator/src/config/string_array.c" "'
            + folder
            + 'NICMx/FORT-validator/src/init.c" "'
            + folder
            + 'NICMx/FORT-validator/src/daemon.c" "'
            + folder
            + 'NICMx/FORT-validator/src/config.c" "'
            + folder
            + 'NICMx/FORT-validator/src/types/address.c" "'
            + folder
            + 'NICMx/FORT-validator/src/nid.c" "'
            + folder
            + 'NICMx/FORT-validator/src/extension.c" "'
            + folder
            + 'NICMx/FORT-validator/src/thread_var.c" "'
            + folder
            + 'NICMx/FORT-validator/src/incidence/incidence.c" "'
            + folder
            + 'NICMx/FORT-validator/src/state.c" "'
            + folder
            + 'NICMx/FORT-validator/src/cert_stack.c" "'
            + folder
            + 'NICMx/FORT-validator/src/crypto/hash.c" "'
            + folder
            + 'NICMx/FORT-validator/src/common.c" "'
            + folder
            + 'NICMx/FORT-validator/src/json_handler.c" "'
            + folder
            + 'NICMx/FORT-validator/src/data_structure/path_builder.c" "'
            + folder
            + 'NICMx/FORT-validator/src/types/uri.c" "'
            + folder
            + 'NICMx/FORT-validator/src/file.c" "'
            + folder
            + 'NICMx/FORT-validator/src/str_token.c" "'
            + folder
            + 'NICMx/FORT-validator/src/resource.c" "'
            + folder
            + 'NICMx/FORT-validator/src/config/work_offline.c" "'
            + folder
            + 'NICMx/FORT-validator/src/http/http.c" "'
            + folder
            + 'NICMx/FORT-validator/src/cache/local_cache.c" "'
            + folder
            + 'NICMx/FORT-validator/src/resource/asn.c" "'
            + folder
            + 'NICMx/FORT-validator/src/resource/ip6.c" "'
            + folder
            + 'NICMx/FORT-validator/src/rpp.c" "'
            + folder
            + 'NICMx/FORT-validator/src/object/tal.c" "'
            + folder
            + 'NICMx/FORT-validator/src/rtr/db/db_table.c" "'
            + folder
            + 'NICMx/FORT-validator/src/object/certificate.c" "'
            + folder
            + 'NICMx/FORT-validator/src/rtr/db/vrps.c" "'
            + folder
            + 'NICMx/FORT-validator/src/line_file.c" "'
            + folder
            + 'NICMx/FORT-validator/src/crypto/base64.c" "'
            + folder
            + 'NICMx/FORT-validator/src/sorted_array.c" "'
            + folder
            + 'NICMx/FORT-validator/src/rrdp.c" "'
            + folder
            + 'NICMx/FORT-validator/src/rsync/rsync.c" "'
            + folder
            + 'NICMx/FORT-validator/src/resource/ip4.c" "'
            + folder
            + 'NICMx/FORT-validator/src/object/crl.c" "'
            + folder
            + 'NICMx/FORT-validator/src/object/roa.c" "'
            + folder
            + 'NICMx/FORT-validator/src/object/ghostbusters.c" "'
            + folder
            + 'NICMx/FORT-validator/src/types/router_key.c" "'
            + folder
            + 'NICMx/FORT-validator/src/rtr/db/delta.c" "'
            + folder
            + 'NICMx/FORT-validator/src/algorithm.c" "'
            + folder
            + 'NICMx/FORT-validator/src/object/name.c" "'
            + folder
            + 'NICMx/FORT-validator/src/asn1/decode.c" "'
            + folder
            + 'NICMx/FORT-validator/src/certificate_refs.c" "'
            + folder
            + 'NICMx/FORT-validator/src/object/manifest.c" "'
            + folder
            + 'NICMx/FORT-validator/src/rtr/db/deltas_array.c" "'
            + folder
            + 'NICMx/FORT-validator/src/slurm/db_slurm.c" "'
            + folder
            + 'NICMx/FORT-validator/src/output_printer.c" "'
            + folder
            + 'NICMx/FORT-validator/src/types/vrp.c" "'
            + folder
            + 'NICMx/FORT-validator/src/types/serial.c" "'
            + folder
            + 'NICMx/FORT-validator/src/xml/relax_ng.c" "'
            + folder
            + 'NICMx/FORT-validator/src/validation_handler.c" "'
            + folder
            + 'NICMx/FORT-validator/src/object/signed_object.c" "'
            + folder
            + 'NICMx/FORT-validator/src/object/vcard.c" "'
            + folder
            + 'NICMx/FORT-validator/src/types/delta.c" "'
            + folder
            + 'NICMx/FORT-validator/src/slurm/slurm_loader.c" "'
            + folder
            + 'NICMx/FORT-validator/src/asn1/signed_data.c" "'
            + folder
            + 'NICMx/FORT-validator/src/asn1/content_info.c" "'
            + folder
            + 'NICMx/FORT-validator/src/asn1/oid.c" "'
            + folder
            + 'NICMx/FORT-validator/src/slurm/slurm_parser.c" "'
            + folder
            + 'NICMx/FORT-validator/src/config/curl_offset.c" -lxml2 -lc -ljansson -lssl -lcrypto -lcurl',  # Required packages: openssl, libcurl-dev. Requires you to go into their build directory and run ./autogen.sh && ./configure
            "mz-automation/libiec61850": '-I"'
            + folder
            + 'mz-automation/libiec61850/config" -I"'
            + folder
            + 'mz-automation/libiec61850/src/common/inc" -I"'
            + folder
            + 'mz-automation/libiec61850/hal/inc" -I"'
            + folder
            + 'mz-automation/libiec61850/src/mms/inc" "'
            + folder
            + 'mz-automation/libiec61850/hal/memory/lib_memory.c"',  # test
            "specinfo-ua/UAPKI": '-I"'
            + folder
            + 'specinfo-ua/UAPKI/library/uapkif/include" -I"'
            + folder
            + 'specinfo-ua/UAPKI/library/uapkic/include" "'
            + folder
            + 'specinfo-ua/UAPKI/library/uapkic/src/stacktrace.c" "'
            + folder
            + 'specinfo-ua/UAPKI/library/uapkic/src/byte-array.c" "'
            + folder
            + 'specinfo-ua/UAPKI/library/uapkic/src/pthread-impl.c" "'
            + folder
            + 'specinfo-ua/UAPKI/library/uapkic/src/byte-utils-internal.c"',  # test
            "o-ran-sc/archived-ric-plt-resource-status-processor": "-DASN_DISABLE_OER_SUPPORT",
            "o-ran-sc/archived-ric-app-kpimon": "-DASN_DISABLE_OER_SUPPORT",
            "o-ran-sc/archived-ric-app-admin": "-DASN_DISABLE_OER_SUPPORT",
            "copslock/o-ran_it_test": "-DASN_DISABLE_OER_SUPPORT",
            "ttiger0114/UERANSIM": "-DASN_DISABLE_OER_SUPPORT",
            "tosan79/ueransimplusplus": "-DASN_DISABLE_OER_SUPPORT",
            "rjaeka456/UERANSIM-LITE": "-DASN_DISABLE_OER_SUPPORT",
            "tsylla/5grail-emu5gnet": "-DASN_DISABLE_OER_SUPPORT",
            "fillabs/fsmsggen": "-DASN_DISABLE_XER_SUPPORT -DASN_DISABLE_OER_SUPPORT -DASN_DISABLE_APER_SUPPORT -DASN_DISABLE_PRINT_SUPPORT -DASN_DISABLE_RFILL_SUPPORT -DASN_DISABLE_JER_SUPPORT",
            "asn1_codec/ieee_1609dot2_api": "-DASN_DISABLE_OER_SUPPORT",
            "a4a881d4/oai": "-include linux/slab.h",
            "alexandre-huff/bouncer-xapp": '-DASN_DISABLE_OER_SUPPORT -I"'
            + folder
            + 'alexandre-huff/bouncer-xapp/Bouncer/asn1c_defs/bouncer"',
            "x1ng-z/IndigoSCADA-1": '-I"'
            + folder
            + 'x1ng-z/IndigoSCADA-1/src/drivers/iec61850/protocol/config" -I"'
            + folder
            + 'x1ng-z/IndigoSCADA-1/src/drivers/iec61850/protocol/hal/inc" -I"'
            + folder
            + 'x1ng-z/IndigoSCADA-1/src/drivers/iec61850/protocol/hal/memory/lib_memory.c"',
            "Montimage/mmt-dpi": '-I"'
            + folder
            + 'Montimage/mmt-dpi/src/mmt_mobile/asn1c/s1ap" "'
            + folder
            + 'Montimage/mmt-dpi/src/mmt_mobile/asn1c/s1ap/*.c"',
            # "roema/Open-Glider-Network-Groundstation": "-DASN_DISABLE_OER_SUPPORT", # Causes more OER errors...
            "akorb/alias_cert_extension": "-DASN_DISABLE_OER_SUPPORT",
            # "CazYokoyama/Open-Glider-Network-Groundstation": "-DASN_DISABLE_OER_SUPPORT", # Causes more OER errors...
            "ToriRobert/o1": '-I"' + folder + 'ToriRobert/o1/src/cm"',
            "penguinic77/odu-l2": '-I"' + folder + 'penguinic77/odu-l2/src/cm"',
            "rightbear/OSC_L2": '-include stdio.h -I"'
            + folder
            + 'rightbear/OSC_L2/src/cm"',
            "Risteel/E2_Term": '-include stdio.h -I"'
            + folder
            + 'Risteel/E2_Term/src/cm"',
            "bmw-ece-ntust/MIMO-Scheduler-on-Sch-Slice-Based": '-include stdio.h -I"'
            + folder
            + 'bmw-ece-ntust/MIMO-Scheduler-on-Sch-Slice-Based/src/cm"',
            "alexandre-huff/bouncer-rc": '-I"'
            + folder
            + 'alexandre-huff/bouncer-rc/Bouncer/asn1c_defs/bouncer" "'
            + folder
            + 'alexandre-huff/bouncer-rc/Bouncer/asn1c_defs/bouncer"',
            "CCI-NextG-Testbed/bouncer-rc": '-I"'
            + folder
            + 'CCI-NextG-Testbed/bouncer-rc/Bouncer/asn1c_defs/bouncer" "'
            + folder
            + 'CCI-NextG-Testbed/bouncer-rc/Bouncer/asn1c_defs/bouncer"/*.c',
            "kryptowirelabs/comets-xrf": "-DASN_DISABLE_OER_SUPPORT",
            "tolgaoa/xrfoauth": "-DASN_DISABLE_OER_SUPPORT",
            "o-ran-sc/ric-plt-libe2ap": "-DASN_DISABLE_OER_SUPPORT",
            "chuanqi1997/MT76X8-OpenWrt-18.06": '-I"'
            + folder
            + 'chuanqi1997/MT76X8-OpenWrt-18.06/package/app/libs/libiec61850/src/libiec61850-1.4.0/config" -I"'
            + folder
            + 'chuanqi1997/MT76X8-OpenWrt-18.06/package/app/libs/libiec61850/src/libiec61850-1.4.0/src/common/inc"',
            "camaison/blockchain-security-layer-in-smart-grid": '-I"'
            + folder
            + 'camaison/blockchain-security-layer-in-smart-grid/GOOSE_Client/libiec61850_mod/config"',
            "matheusxd8147/VIED": '-I"'
            + folder
            + 'matheusxd8147/VIED/config" -I"'
            + folder
            + 'matheusxd8147/VIED/src/common/inc"',
            "jeewood/YTHDY": '-I"'
            + folder
            + 'jeewood/YTHDY/config" -I"'
            + folder
            + 'jeewood/YTHDY/src/common/inc"',
            "chuanqi1997/NUC980-OpenWrt-LEDE": '-I"'
            + folder
            + 'chuanqi1997/NUC980-OpenWrt-LEDE/package/app/libs/libiec61850/src/libiec61850-1.4.0/config" -I"'
            + folder
            + 'chuanqi1997/NUC980-OpenWrt-LEDE/package/app/libs/libiec61850/src/libiec61850-1.4.0/src/common/inc"',
            "smartgridadsc/OpenPLC61850": '-I"'
            + folder
            + 'smartgridadsc/OpenPLC61850/utils/libiec61850_src/config" -I"'
            + folder
            + 'smartgridadsc/OpenPLC61850/utils/libiec61850_src/src/common/inc" -I"'
            + folder
            + 'smartgridadsc/OpenPLC61850/utils/libiec61850_src/src/mms/inc" -I"'
            + folder
            + 'smartgridadsc/OpenPLC61850/utils/libiec61850_src/hal/inc" "'
            + folder
            + 'smartgridadsc/OpenPLC61850/utils/libiec61850_src/hal/memory/lib_memory.c"',
            "qjwanglll/Industrial-Network-Protocol": '-I"'
            + folder
            + 'qjwanglll/Industrial-Network-Protocol/libiec61850-1.3.1/libiec61850-1.3.1/config" -I"'
            + folder
            + 'qjwanglll/Industrial-Network-Protocol/libiec61850-1.3.1/libiec61850-1.3.1/hal/inc" "'
            + folder
            + "qjwanglll/Industrial-Network-Protocol/libiec61850-1.3.1/libiec61850-1.3.1/hal/memory/lib_memory.c",
            "enscada/IndigoSCADA": '-I"'
            + folder
            + 'enscada/IndigoSCADA/src/drivers/iec61850/protocol/config" -I"'
            + folder
            + 'enscada/IndigoSCADA/src/drivers/iec61850/protocol/hal/inc" "'
            + folder
            + 'enscada/IndigoSCADA/src/drivers/iec61850/protocol/hal/memory/lib_memory.c"',
            "praveen-emsec/Gridpot": '-I"'
            + folder
            + 'praveen-emsec/Gridpot/libiec61850-0.8.5/config" -I"'
            + folder
            + 'praveen-emsec/Gridpot/libiec61850-0.8.5/src/common/inc" "'
            + folder
            + 'praveen-emsec/Gridpot/libiec61850-0.8.5/src/common/lib_memory.c"',
            "lingtorp/iec61850-server": '-I"'
            + folder
            + 'lingtorp/iec61850-server/libiec61850/config" -I"'
            + folder
            + 'lingtorp/iec61850-server/libiec61850/src/common/inc" "'
            + folder
            + 'lingtorp/iec61850-server/libiec61850/src/common/lib_memory.c"',
            "lk021x/libiec61850": '-I"'
            + folder
            + 'lk021x/libiec61850/config" -I"'
            + folder
            + 'lk021x/libiec61850/src/common/inc" "'
            + folder
            + "lk021x/libiec61850/src/common/lib_memory.c",
            "jonathanxavier/IndigoSCADA": '-I"'
            + folder
            + 'jonathanxavier/IndigoSCADA/src/drivers/iec61850/protocol/config"  -I"'
            + folder
            + 'jonathanxavier/IndigoSCADA/src/drivers/iec61850/protocol/hal/inc" '
            + folder
            + "jonathanxavier/IndigoSCADA/src/drivers/iec61850/protocol/hal/memory/lib_memory.c",
            "minhdtb/libiec": '-I"'
            + folder
            + 'minhdtb/libiec/config" -I"'
            + folder
            + 'minhdtb/libiec/src/common/inc" "'
            + folder
            + 'minhdtb/libiec/src/common/lib_memory.c"',
            "sk4ld/gridpot": '-I"'
            + folder
            + 'sk4ld/gridpot/libiec61850-0.8.5/config" -I"'
            + folder
            + 'sk4ld/gridpot/libiec61850-0.8.5/src/common/inc" "'
            + folder
            + 'sk4ld/gridpot/libiec61850-0.8.5/src/common/lib_memory.c"',
            "aligungr/UERANSIM": "-DASN_DISABLE_OER_SUPPORT",
            "NJ-SunJiawei/oset-platform": "-DASN_DISABLE_OER_SUPPORT",
            "osmocom/libasn1c": "-losmocore -ltalloc",
            "o-ran-sc/o-du-l2": '-I"'
            + folder
            + 'o-ran-sc/o-du-l2/src/cm"',  # -include \"" + folder + "o-ran-sc/o-du-l2/src/cm/envdep.h\"",
            "IOT-DSA/dslink-c-iec61850": '-I"'
            + folder
            + 'IOT-DSA/dslink-c-iec61850/libiec61850/config" -I"'
            + folder
            + 'IOT-DSA/dslink-c-iec61850/libiec61850/src/common/inc" "'
            + folder
            + 'IOT-DSA/dslink-c-iec61850/libiec61850/src/common/lib_memory.c"',
            "feuvan/libiec61850": '-I"'
            + folder
            + 'feuvan/libiec61850/config" -I"'
            + folder
            + 'feuvan/libiec61850/src/common/inc" "'
            + folder
            + 'feuvan/libiec61850/src/common/lib_memory.c"',
            "mgrebla/IEC61850RelaySTM32F7": '-I"'
            + folder
            + 'mgrebla/IEC61850RelaySTM32F7/libiec61850/src" -I"'
            + folder
            + 'mgrebla/IEC61850RelaySTM32F7/libiec61850/src/common/inc" -I"'
            + folder
            + 'mgrebla/IEC61850RelaySTM32F7/libiec61850/src/hal/inc" -I"'
            + folder
            + 'mgrebla/IEC61850RelaySTM32F7/libiec61850/src/mms/inc" "'
            + folder
            + 'mgrebla/IEC61850RelaySTM32F7/libiec61850/src/common/lib_memory.c"',
            "Calctopia-OpenSource/cothority": "-include openssl/evp.h -lssl",
            "spire-resilient-systems/spire": '-I"'
            + folder
            + 'spire-resilient-systems/spire/libiec61850/config" -I"'
            + folder
            + 'spire-resilient-systems/spire/libiec61850/hal/inc/lib_memory.h" "'
            + folder
            + 'spire-resilient-systems/spire/libiec61850/hal/memory/lib_memory.c"',
            "zjcszn/embeded-lib": '-I"'
            + folder
            + 'zjcszn/embeded-lib/1. library/1.8 protocol/iec/libiec61850-1.5.3/config" -I"'
            + folder
            + 'zjcszn/embeded-lib/1. library/1.8 protocol/iec/libiec61850-1.5.3/hal/inc" "'
            + folder
            + 'zjcszn/embeded-lib/1. library/1.8 protocol/iec/libiec61850-1.5.3/hal/memory/lib_memory.c"',
            "copslock/o-ran-sc_ric-app_kpimon": "-DASN_DISABLE_OER_SUPPORT",
            "johnson-penguin/slice_enable_scheduler": '-I"'
            + folder
            + 'johnson-penguin/slice_enable_scheduler/src/cm"',
            "stevenpsm/GM_SM2": "-include stddef.h -include stdint.h",
            "wineslab/colosseum-scope-e2": '-DASN_DISABLE_OER_SUPPORT -I"'
            + folder
            + 'wineslab/colosseum-scope-e2/src/cm"',
            "ldm5180/hammerhead": '-I"'
            + folder
            + 'ldm5180/hammerhead/util" -I/usr/include/glib-2.0',
            "pragnyakiri/UERANSIM-Handover": "-DASN_DISABLE_OER_SUPPORT",
            "rjaeka456/UERAN-EXTENSION": "-DASN_DISABLE_OER_SUPPORT",
            "huahuaLover/UERANSIM": "-DASN_DISABLE_OER_SUPPORT",
            "VeriDevOps/mmt-dpi": '-I"'
            + folder
            + 'VeriDevOps/mmt-dpi/src/mmt_mobile/asn1c/s1ap" "'
            + folder
            + 'VeriDevOps/mmt-dpi/src/mmt_mobile/asn1c/s1ap/*.c"',
            "binhfdv/srv6-dmm": "-DASN_DISABLE_OER_SUPPORT",
            "GM_SM2/sm2der": "-include stdint.h",
            "nextepc/nextepc": '-D_XOPEN_SOURCE=700 -D_DEFAULT_SOURCE -DSIZEOF_VOIDP=4 -DHAVE_STRUCT_TM_TM_GMTOFF -include semaphore.h -include pthread.h -include fcntl.h -include errno.h -include sys/stat.h -include unistd.h -include stdio.h -include sys/time.h -include time.h -include stdarg.h -include string.h -include linux/limits.h -I"'
            + folder
            + 'nextepc/nextepc/lib/core/include/arch/unix" -I"'
            + folder
            + 'nextepc/nextepc/lib/core/include" "'
            + folder
            + 'nextepc/nextepc/lib/core/src/unix/pkbuf.c" "'
            + folder
            + 'nextepc/nextepc/lib/core/src/unix/file.c" "'
            + folder
            + 'nextepc/nextepc/lib/core/src/unix/thread.c" "'
            + folder
            + 'nextepc/nextepc/lib/core/src/unix/mutex.c" "'
            + folder
            + 'nextepc/nextepc/lib/core/src/unix/time.c" "'
            + folder
            + 'nextepc/nextepc/lib/core/src/debug.c" "'
            + folder
            + 'nextepc/nextepc/lib/core/src/unix/semaphore.c"',
            "vaggelis-sudo/5G-UE-SecurityTesting": '-D_GNU_SOURCE -include netdb.h -fpermissive -DASN_DISABLE_JER_SUPPORT -DHAVE_STRUCT_TM_TM_GMTOFF -D_XOPEN_SOURCE=600 -DHAVE_STRERROR_R -DSTRERROR_R_CHAR_P -DASN_DISABLE_OER_SUPPORT -I"'
            + folder
            + 'vaggelis-sudo/5G-UE-SecurityTesting/open5gs/lib" -I"'
            + folder
            + 'vaggelis-sudo/5G-UE-SecurityTesting/open5gs/build/lib" -I"'
            + folder
            + 'vaggelis-sudo/5G-UE-SecurityTesting/open5gs/build/lib/core" "'
            + folder
            + 'vaggelis-sudo/5G-UE-SecurityTesting/open5gs/lib/core/ogs-log.c" "'
            + folder
            + 'vaggelis-sudo/5G-UE-SecurityTesting/open5gs/lib/core/ogs-abort.c" "'
            + folder
            + 'vaggelis-sudo/5G-UE-SecurityTesting/open5gs/lib/core/ogs-strings.c" "'
            + folder
            + 'vaggelis-sudo/5G-UE-SecurityTesting/open5gs/lib/core/ogs-memory.c" "'
            + folder
            + 'vaggelis-sudo/5G-UE-SecurityTesting/open5gs/lib/core/ogs-pkbuf.c" "'
            + folder
            + 'vaggelis-sudo/5G-UE-SecurityTesting/open5gs/lib/core/ogs-core.c" "'
            + folder
            + 'vaggelis-sudo/5G-UE-SecurityTesting/open5gs/lib/core/ogs-hash.c" "'
            + folder
            + 'vaggelis-sudo/5G-UE-SecurityTesting/open5gs/lib/core/ogs-errno.c" "'
            + folder
            + 'vaggelis-sudo/5G-UE-SecurityTesting/open5gs/lib/core/ogs-time.c" "'
            + folder
            + 'vaggelis-sudo/5G-UE-SecurityTesting/open5gs/lib/core/ogs-socket.c" "'
            + folder
            + 'vaggelis-sudo/5G-UE-SecurityTesting/open5gs/lib/core/ogs-tlv.c" "'
            + folder
            + 'vaggelis-sudo/5G-UE-SecurityTesting/open5gs/lib/core/ogs-sockaddr.c" -ltalloc',
            "SyNSec-den/5GBaseChecker": '-DASN_DISABLE_OER_SUPPORT -DASN_DISABLE_XER_SUPPORT -I"'
            + folder
            + 'SyNSec-den/5GBaseChecker/StateSynth/modified_cellular_stack/5GBaseChecker_Core/lib" -I"'
            + folder
            + 'SyNSec-den/5GBaseChecker/StateSynth/modified_cellular_stack/5GBaseChecker_Core/lib/proto" -I"'
            + folder
            + 'SyNSec-den/5GBaseChecker/StateSynth/modified_cellular_stack/5GBaseChecker_Core/build/lib" -I"'
            + folder
            + 'SyNSec-den/5GBaseChecker/StateSynth/modified_cellular_stack/5GBaseChecker_Core/build/lib/core" -I"'
            + folder
            + 'SyNSec-den/5GBaseChecker/StateSynth/modified_cellular_stack/5GBaseChecker_Core/lib/core" "'
            + folder
            + 'SyNSec-den/5GBaseChecker/StateSynth/modified_cellular_stack/5GBaseChecker_Core/lib/core/ogs-log.c" "'
            + folder
            + 'SyNSec-den/5GBaseChecker/StateSynth/modified_cellular_stack/5GBaseChecker_Core/lib/core/ogs-abort.c" "'
            + folder
            + 'SyNSec-den/5GBaseChecker/StateSynth/modified_cellular_stack/5GBaseChecker_Core/lib/core/ogs-strings.c" "'
            + folder
            + 'SyNSec-den/5GBaseChecker/StateSynth/modified_cellular_stack/5GBaseChecker_Core/lib/core/ogs-memory.c" "'
            + folder
            + 'SyNSec-den/5GBaseChecker/StateSynth/modified_cellular_stack/5GBaseChecker_Core/lib/core/ogs-pkbuf.c" "'
            + folder
            + 'SyNSec-den/5GBaseChecker/StateSynth/modified_cellular_stack/5GBaseChecker_Core/lib/core/ogs-core.c" "'
            + folder
            + 'SyNSec-den/5GBaseChecker/StateSynth/modified_cellular_stack/5GBaseChecker_Core/lib/core/ogs-hash.c" "'
            + folder
            + 'SyNSec-den/5GBaseChecker/StateSynth/modified_cellular_stack/5GBaseChecker_Core/lib/core/ogs-errno.c" "'
            + folder
            + 'SyNSec-den/5GBaseChecker/StateSynth/modified_cellular_stack/5GBaseChecker_Core/lib/core/ogs-time.c" "'
            + folder
            + 'SyNSec-den/5GBaseChecker/StateSynth/modified_cellular_stack/5GBaseChecker_Core/lib/core/ogs-socket.c" "'
            + folder
            + 'SyNSec-den/5GBaseChecker/StateSynth/modified_cellular_stack/5GBaseChecker_Core/lib/core/ogs-tlv.c" "'
            + folder
            + 'SyNSec-den/5GBaseChecker/StateSynth/modified_cellular_stack/5GBaseChecker_Core/lib/core/ogs-sockaddr.c" -ltalloc',
            "ika-rwth-aachen/etsi_its_messages": '-I"'
            + folder
            + 'ika-rwth-aachen/etsi_its_messages/etsi_its_coding/etsi_its_cam_coding/include" -I"'
            + folder
            + 'ika-rwth-aachen/etsi_its_messages/etsi_its_coding/etsi_its_denm_coding/include"',
            "Next-Flip/Momentum-Apps": '-I"'
            + folder
            + 'Next-Flip/Momentum-Apps/seader/lib/asn1"',
            "wineslab/colosseum-near-rt-ric": "-DASN_DISABLE_OER_SUPPORT",  # + folder + "wineslab/colosseum-near-rt-ric/setup/xapp-sm-connector/asn1c_defs\"/*.c",
            "jks-prv/Beagle_SDR_GPS": '-I"'
            + folder
            + 'jks-prv/Beagle_SDR_GPS/extensions/HFDL/include/libacars-2"',
            "flydog-sdr/FlyDog_SDR_GPS": '-I"'
            + folder
            + 'flydog-sdr/FlyDog_SDR_GPS/extensions/HFDL/include/libacars-2"',
            "uplusware/erisemail": '-I"'
            + folder
            + 'uplusware/erisemail/src/ldap_asn1"',
            "OreoFroyo/UERANSIM_beforehandHO": "-DASN_DISABLE_OER_SUPPORT",
            "saffanazyan07/z-agf": "-DASN_DISABLE_OER_SUPPORT",
            "Haw984/gNB_UERANSIM": "-DASN_DISABLE_OER_SUPPORT",
            "yolo00001/UERANSIM": "-DASN_DISABLE_OER_SUPPORT",
            "saffanazyan07/z-UERANSIM-W-AGF": "-DASN_DISABLE_OER_SUPPORT",
            "enable-intelligent-containerized-5g/ueransim": "-DASN_DISABLE_OER_SUPPORT",
            "denerkr/edgelb": "-DASN_DISABLE_OER_SUPPORT",
            "LABORA-INF-UFG/Infocom2023-RIC-O-Demo": "-DASN_DISABLE_OER_SUPPORT",
            "IIITV-5G-and-Edge-Computing-Activity/5G-Network-Setup-and-Testing": "-DASN_DISABLE_OER_SUPPORT",
            "natanzi/srsran_test": "-DASN_DISABLE_OER_SUPPORT",
            "ivlevaleksandr4/FastTrackTelecom": "-DASN_DISABLE_OER_SUPPORT",
            "onosproject/onos-e2-sm": "-DASN_DISABLE_OER_SUPPORT",
            "wineslab/xapp-oai": "-DASN_DISABLE_OER_SUPPORT",
            "Paloma-96/xapp-oai": "-DASN_DISABLE_OER_SUPPORT",
            # "ms-van3t-devs/ms-van3t": "-DASN_DISABLE_OER_SUPPORT",
            "wineslab/colosseum-scope-e2": '-I"'
            + folder
            + 'wineslab/colosseum-scope-e2/src/cm"',
            "chuanqi1997/NUC980-OpenWrt-LEDE": '-I"'
            + folder
            + 'chuanqi1997/NUC980-OpenWrt-LEDE/package/app/libs/lib60870/src/lib60870-C/src/hal/inc" -I"'
            + folder
            + 'chuanqi1997/NUC980-OpenWrt-LEDE/package/app/libs/libiec61850/src/libiec61850-1.4.0/config" -I"'
            + folder
            + 'chuanqi1997/NUC980-OpenWrt-LEDE/package/app/libs/libiec61850/src/libiec61850-1.4.0/src/common/inc" -I"'
            + folder
            + 'chuanqi1997/NUC980-OpenWrt-LEDE/package/app/libs/libiec61850/src/libiec61850-1.4.0/src/mms/inc" -I"'
            + folder
            + 'chuanqi1997/NUC980-OpenWrt-LEDE/package/app/libs/lib60870/src/lib60870-C/config" "'
            + folder
            + 'chuanqi1997/NUC980-OpenWrt-LEDE/package/app/libs/lib60870/src/lib60870-C/src/hal/memory/lib_memory.c"',  #
            "l4es/IndustrialAutomation": "",  # Multiple defined ber_* - because we're including multiple skeleton folders
            # "ika-rwth-aachen/etsi_its_messages": "", # Multiple defintiions of ASN.1 structures.
            "rwl/libiec61850": "",  # Multiple definitions of ASN.1 structures
            "usdot-fhwa-OPS/V2X-Hub": "",  # Multiple ASN.1 struct defs
            "tolgaoa/devdep5g": "",  # Multiple ASN.1 struct defs
            "zxcwhale/android_hal_gpsbds": "",  # Multiple ASN.1 struct defs
            "pintauroo/5G_LMF": "",  # Multiple ASN.1 struct defs
            "FredericLeroy/libngapcodec": "",  # Multiple ASN.1 struct defs
            "": "",
        }

    def get_ignored_files(self, source: str, repo: str, files: list) -> str:
        cmd = f'find "{source}" -name "*.c" | grep -v'

        for file in self.ignored_files:
            cmd += f' -e "{file}$"'

        if repo not in self.additional_ignored_files:
            return cmd  # + " | sed 's/.*/\"&\"/'"

        for file in self.additional_ignored_files[repo]:
            cmd += f' -e "{file}$"'

        return cmd  # + " | sed 's/.*/\"&\"/'"

    def get_folder(self):
        return self.folder


class GitHubCompile:
    def __init__(self, repos, folder: Path, output_binaries_folder: Path):
        self.repos = repos
        self.config = GitHubCompileConfig(folder)
        self.output = output_binaries_folder

    def _build_compile_command(self, curr_repo, copy_repo, includes, sources=None):
        cmd = (
            "gcc -O0 -g -D'in_addr_t=uint32_t' -I\""
            + curr_repo
            + '" -I"'
            + curr_repo
            + '/src" -I"'
            + curr_repo
            + '/include"'
            + includes
            + ' -o "'
            + curr_repo
            + "/"
            + copy_repo
            + '.bin" -include stddef.h -include stdint.h -include sys/types.h -include netinet/in.h -include arpa/inet.h '
        )
        if sources and len(sources) > 10:  # Make sure its more than just files=(())
            # return sources + " | xargs " + cmd
            cmd = (
                "gcc -O0 -g -D'in_addr_t=uint32_t' -I\""
                + curr_repo
                + '" -I"'
                + curr_repo
                + '/src" -I"'
                + curr_repo
                + '/include"'
                + includes
                + ' -o "'
                + curr_repo
                + "/"
                + copy_repo
                + '.bin" -include stddef.h -include stdint.h -include sys/types.h -include netinet/in.h -include arpa/inet.h "${files[@]}" '
            )
        return cmd

    def _process_repo(self, repo, code_locs, script_file):
        header, source = code_locs[0], code_locs[1]
        includes = ""
        sources = "files=($("

        for h in header:
            includes = includes + ' -I"' + str(h) + '"'
        for s in source:
            # Comment out the functionality that compiles multiple asn1c folders. Do this because we often have conflicting symbols.
            # Re-add the functionality to handle multiple skeleton folders when support for multiple skeleton folders is fixed.
            sources = sources + self.config.get_ignored_files(
                str(s), repo, self.config.ignored_files
            )
            break

        sources = "" + sources + "))\n"

        copy_repo = repo.replace("/", ".")
        curr_repo = str(self.config.get_folder() / repo)

        compile_command = self._build_compile_command(
            curr_repo, copy_repo, includes, sources
        )

        if repo in self.config.additional_compile_options:
            compile_command = (
                compile_command + self.config.additional_compile_options[repo] + " "
            )

        compile_command = (
            compile_command
            + str(resources.files("GitHub_Study.data").joinpath("base.cpp"))
            + " -lm\n"
        )

        build_step = (
            'if [ -f "'
            + curr_repo
            + '/meson.build" ]; then (cd "'
            + curr_repo
            + '" && meson setup build && ninja -C build -j8 && '
            + 'built_bin=$(find build -maxdepth 2 -type f -executable -printf "%T@ %p\n" | sort -nr | head -n 1 | cut -d" " -f2-) && '
            + 'if [ -n "$built_bin" ]; then mv -f "$built_bin" "'
            + curr_repo
            + "/"
            + copy_repo
            + '.bin"; fi); '
            + 'elif [ -f "'
            + curr_repo
            + '/build/build.ninja" ]; then (cd "'
            + curr_repo
            + '" && ninja -C build -j8 && '
            + 'built_bin=$(find build -maxdepth 2 -type f -executable -printf "%T@ %p\n" | sort -nr | head -n 1 | cut -d" " -f2-) && '
            + 'if [ -n "$built_bin" ]; then mv -f "$built_bin" "'
            + curr_repo
            + "/"
            + copy_repo
            + '.bin"; fi); '
            + 'elif [ -f "'
            + curr_repo
            + '/build.ninja" ]; then (cd "'
            + curr_repo
            + '" && ninja -j8 && '
            + 'built_bin=$(find . -maxdepth 2 -type f -executable -printf "%T@ %p\n" | sort -nr | head -n 1 | cut -d" " -f2-) && '
            + 'if [ -n "$built_bin" ]; then mv -f "$built_bin" "'
            + curr_repo
            + "/"
            + copy_repo
            + '.bin"; fi); '
            + 'elif [ -f "'
            + curr_repo
            + '/CMakeLists.txt" ]; then (cd "'
            + curr_repo
            + '" && mkdir -p build && cd build && cmake .. && (ninja -C . -j8 || make -j8) && '
            + 'built_bin=$(find . -maxdepth 2 -type f -executable -printf "%T@ %p\n" | sort -nr | head -n 1 | cut -d" " -f2-) && '
            + 'if [ -n "$built_bin" ]; then mv -f "$built_bin" "'
            + curr_repo
            + "/"
            + copy_repo
            + '.bin"; fi); '
            + 'elif [ -f "'
            + curr_repo
            + '/configure.ac" ] || [ -f "'
            + curr_repo
            + '/Makefile.am" ] || [ -f "'
            + curr_repo
            + '/makefile.am" ]; then (cd "'
            + curr_repo
            + '" && autoreconf -i && ./configure && make -j8 && '
            + 'built_bin=$(find . -maxdepth 2 -type f -executable -printf "%T@ %p\n" | sort -nr | head -n 1 | cut -d" " -f2-) && '
            + 'if [ -n "$built_bin" ]; then mv -f "$built_bin" "'
            + curr_repo
            + "/"
            + copy_repo
            + '.bin"; fi); '
            + 'elif [ -f "'
            + curr_repo
            + '/Makefile" ] || [ -f "'
            + curr_repo
            + '/makefile" ]; then (cd "'
            + curr_repo
            + '" && make -j8 && '
            + 'built_bin=$(find . -maxdepth 2 -type f -executable -printf "%T@ %p\n" | sort -nr | head -n 1 | cut -d" " -f2-) && '
            + 'if [ -n "$built_bin" ]; then mv -f "$built_bin" "'
            + curr_repo
            + "/"
            + copy_repo
            + '.bin"; fi); '
            + "fi\n"
        )
        script_file.write(build_step)
        script_file.write(sources)
        script_file.write(compile_command)
        script_file.write(
            "echo \"Done trying to compile binary '"
            + str(self.config.get_folder() / repo / (copy_repo + ".bin"))
            + "'\"\n"
        )

    def compile_repositories(self):
        with open("output_script.sh", "w") as script_file:
            for repo, code_locs in self.repos.items():
                copy_repo = repo.replace("/", ".")
                bin_path = self.config.get_folder() / repo / (copy_repo + ".bin")
                if (
                    bin_path.exists()
                ):  # skip compiling repo if we already have a bin file for it.
                    bin_path.unlink()
                self._process_repo(repo, code_locs, script_file)

        print("[*] Compile script created, this may take awhile...")

        with open("output.txt", "w") as f:
            subprocess.run(["bash", "output_script.sh"], stdout=f, stderr=f)

        print(
            "[*] Compile script completed, moving successful binaries to output folder..."
        )

        successes, failures = [], []

        for repo, code_locs in self.repos.items():
            copy_repo = repo.replace("/", ".")
            bin_path = self.config.get_folder() / repo / (copy_repo + ".bin")

            if bin_path.exists():
                successes.append(repo)
                shutil.copy2(str(bin_path), str(self.output) + "/" + copy_repo + ".bin")
            else:
                failures.append(repo)

        print("Successes:", successes, "Failures:", failures)
