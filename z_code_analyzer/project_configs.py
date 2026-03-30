"""Per-project analysis configurations for AGF benchmark.

Each project specifies:
- preferred_backend: "svf" or "joern" (which engine gives better results)
- repo_url: source repository
- fuzzer_entry_functions: mapping of benchmark case -> entry functions to trace
  for reachability analysis

These configs were derived from manual analysis of 46 OSS-Fuzz projects
in the AGF benchmark (99 cases total).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ProjectConfig:
    """Analysis configuration for a single project."""
    project: str
    preferred_backend: str  # "svf" or "joern"
    repo_url: str = ""
    fuzzer_entry_functions: dict[str, list[str]] = field(default_factory=dict)
    notes: str = ""


# ── Configurations ──────────────────────────────────────────────────────────

CONFIGS: dict[str, ProjectConfig] = {}


def _register(cfg: ProjectConfig):
    CONFIGS[cfg.project] = cfg


# SVF backend projects (C, Makefile/Autotools, wllvm works well)

_register(ProjectConfig(
    project="apache-httpd",
    preferred_backend="svf",
    fuzzer_entry_functions={
        "fuzz_addr_parse": ["apr_parse_addr_port"],
        "fuzz_tokenize": ["apr_tokenize_to_argv"],
    },
))

_register(ProjectConfig(
    project="brotli",
    preferred_backend="svf",
    fuzzer_entry_functions={
        "decode_fuzzer": ["BrotliDecoderDecompress"],
    },
))

_register(ProjectConfig(
    project="fftw3",
    preferred_backend="svf",
    fuzzer_entry_functions={
        "fftw3_fuzzer": ["fftw_plan_dft_1d"],
    },
))

_register(ProjectConfig(
    project="freerdp",
    preferred_backend="svf",
    fuzzer_entry_functions={
        "TestFuzzCommonAssistanceBinToHexString": ["freerdp_assistance_bin_to_hex_string"],
        "TestFuzzCommonAssistanceHexStringToBin": ["freerdp_assistance_hex_string_to_bin"],
        "TestFuzzCommonAssistanceParseFileBuffer": ["freerdp_assistance_parse_file_buffer"],
        "TestFuzzCryptoCertificateDataSetPEM": ["freerdp_certificate_data_set_pem"],
    },
))

_register(ProjectConfig(
    project="hwloc",
    preferred_backend="svf",
    fuzzer_entry_functions={
        "hwloc_fuzzer": ["hwloc_topology_init"],
    },
))

_register(ProjectConfig(
    project="iperf",
    preferred_backend="svf",
    fuzzer_entry_functions={
        "cjson_fuzzer": ["cJSON_Parse"],
    },
))

_register(ProjectConfig(
    project="jq",
    preferred_backend="svf",
    fuzzer_entry_functions={
        "jq_fuzz_parse": ["jv_parse"],
        "jq_fuzz_parse_extended": ["jv_parse_sized"],
    },
))

_register(ProjectConfig(
    project="libcoap",
    preferred_backend="svf",
    fuzzer_entry_functions={
        "get_asn1_tag_target": ["coap_asn1_tag"],
        "oscore_conf_parse_target": ["coap_new_oscore_conf"],
        "split_uri_target": ["coap_split_uri"],
    },
))

_register(ProjectConfig(
    project="libgit2",
    preferred_backend="svf",
    fuzzer_entry_functions={
        "objects_fuzzer": ["git_odb_read"],
        "patch_parse_fuzzer": ["git_patch_from_buffer"],
    },
))

_register(ProjectConfig(
    project="libpcap",
    preferred_backend="svf",
    fuzzer_entry_functions={
        "fuzz_filter": ["pcap_compile"],
    },
))

_register(ProjectConfig(
    project="libyaml",
    preferred_backend="svf",
    fuzzer_entry_functions={
        "libyaml_loader_fuzzer": ["yaml_parser_load"],
        "libyaml_scanner_fuzzer": ["yaml_parser_scan"],
    },
))

_register(ProjectConfig(
    project="mbedtls",
    preferred_backend="svf",
    fuzzer_entry_functions={
        "fuzz_pkcs7": ["mbedtls_pkcs7_parse_der"],
        "fuzz_x509crl": ["mbedtls_x509_crl_parse"],
        "fuzz_x509crt": ["mbedtls_x509_crt_parse"],
        "fuzz_x509csr": ["mbedtls_x509_csr_parse"],
    },
))

_register(ProjectConfig(
    project="ndpi",
    preferred_backend="svf",
    fuzzer_entry_functions={
        "fuzz_filecfg_categories": ["ndpi_load_categories_file"],
        "fuzz_filecfg_category": ["ndpi_load_category_file"],
        "fuzz_filecfg_config": ["ndpi_load_config_file"],
        "fuzz_filecfg_malicious_ja4": ["ndpi_load_malicious_ja4_file"],
        "fuzz_filecfg_malicious_sha1": ["ndpi_load_malicious_sha1_file"],
        "fuzz_filecfg_protocols": ["ndpi_load_protocols_file"],
        "fuzz_filecfg_risk_domains": ["ndpi_load_risk_domain_file"],
    },
))

_register(ProjectConfig(
    project="php",
    preferred_backend="svf",
    fuzzer_entry_functions={
        "fuzzer-json": ["php_json_decode"],
        "fuzzer-unserialize": ["php_var_unserialize"],
    },
))

_register(ProjectConfig(
    project="pjsip",
    preferred_backend="svf",
    fuzzer_entry_functions={
        "fuzz-dns": ["pj_dns_parse_packet"],
    },
))

_register(ProjectConfig(
    project="strongswan",
    preferred_backend="svf",
    fuzzer_entry_functions={
        "fuzz_crls": ["lib->creds->create"],
        "fuzz_ids": ["identification_create_from_encoding"],
    },
))

# Joern backend projects (C++, CMake, or wllvm fails)

_register(ProjectConfig(
    project="arrow",
    preferred_backend="joern",
    repo_url="https://github.com/apache/arrow.git",
    fuzzer_entry_functions={
        "csv_fuzz": ["FuzzCsvReader"],
        "ipc_file_fuzz": ["FuzzIpcFile"],
        "ipc_stream_fuzz": ["FuzzIpcStream"],
        "ipc_tensor_stream_fuzz": ["FuzzIpcTensorStream"],
    },
    notes="C++ CMake project; only parse cpp/src/arrow/{ipc,csv} for speed",
))

_register(ProjectConfig(
    project="bad_example",
    preferred_backend="joern",
    fuzzer_entry_functions={
        "bad_example_fuzzer": ["uncompress"],
    },
    notes="Trivial test project, calls zlib uncompress",
))

_register(ProjectConfig(
    project="binutils",
    preferred_backend="joern",
    repo_url="https://github.com/bminor/binutils-gdb",
    fuzzer_entry_functions={
        "fuzz_addr2line": ["process_file", "xmalloc", "xstrdup"],
        "fuzz_nm": ["display_file"],
    },
    notes="Large repo; SVF OOMs on Docker build",
))

_register(ProjectConfig(
    project="boost",
    preferred_backend="joern",
    repo_url="https://github.com/boostorg/boost",
    fuzzer_entry_functions={
        "boost_graph_graphviz_fuzzer": ["read_graphviz"],
        "boost_ptree_inforead_fuzzer": ["read_info"],
        "boost_ptree_iniread_fuzzer": ["read_ini"],
        "boost_ptree_jsonread_fuzzer": ["read_json"],
        "boost_ptree_xmlread_fuzzer": ["read_xml"],
    },
    notes="Header-only C++ templates; Joern can only trace shallow calls",
))

_register(ProjectConfig(
    project="clamav",
    preferred_backend="joern",
    repo_url="https://github.com/Cisco-Talos/clamav.git",
    fuzzer_entry_functions={
        "clamav_scanmap_fuzzer": ["cl_scanmap_callback"],
    },
))

_register(ProjectConfig(
    project="curl",
    preferred_backend="joern",
    repo_url="https://github.com/curl/curl.git",
    fuzzer_entry_functions={
        "fuzz_url": ["curl_url", "curl_url_set", "curl_url_get", "curl_url_cleanup"],
    },
))

_register(ProjectConfig(
    project="draco",
    preferred_backend="joern",
    repo_url="https://github.com/google/draco",
    fuzzer_entry_functions={
        "draco_mesh_decoder_fuzzer": ["DecodeMeshFromBuffer"],
        "draco_mesh_decoder_without_dequantization_fuzzer": ["DecodeMeshFromBuffer"],
        "draco_pc_decoder_fuzzer": ["DecodePointCloudFromBuffer"],
    },
))

_register(ProjectConfig(
    project="easywsclient",
    preferred_backend="joern",
    repo_url="https://github.com/dhbaird/easywsclient",
    fuzzer_entry_functions={
        "easyws_fuzzer": ["WebSocket"],
    },
))

_register(ProjectConfig(
    project="flatbuffers",
    preferred_backend="joern",
    repo_url="https://github.com/google/flatbuffers",
    fuzzer_entry_functions={
        "flatbuffers_annotator_fuzzer": ["Annotate", "LoadBinarySchema"],
        "flatbuffers_verifier_fuzzer": ["VerifyMonsterBuffer"],
    },
    notes="C++ templates; shallow reach only",
))

_register(ProjectConfig(
    project="flex",
    preferred_backend="joern",
    repo_url="https://github.com/westes/flex",
    fuzzer_entry_functions={
        "fuzz-main": ["yylex"],
    },
))

_register(ProjectConfig(
    project="gdal",
    preferred_backend="joern",
    repo_url="https://github.com/OSGeo/gdal",
    fuzzer_entry_functions={
        "get_jpeg2000_structure_fuzzer": ["GDALGetJPEG2000Structure", "CPLDestroyXMLNode", "CSLSetNameValue"],
        "gml_geom_import_fuzzer": ["OGR_G_CreateFromGML", "OGR_G_DestroyGeometry"],
        "osr_set_from_user_input_fuzzer": ["OSRSetFromUserInput", "OSRNewSpatialReference", "OSRDestroySpatialReference"],
        "spatialite_geom_import_fuzzer": ["OGRSQLiteImportSpatiaLiteGeometry"],
    },
    notes="Huge project (48K functions); SVF crashes on bitcode",
))

_register(ProjectConfig(
    project="glslang",
    preferred_backend="joern",
    repo_url="https://github.com/KhronosGroup/glslang",
    fuzzer_entry_functions={
        "compile_fuzzer": ["glslang::TShader::parse"],
    },
))

_register(ProjectConfig(
    project="haproxy",
    preferred_backend="joern",
    repo_url="https://github.com/haproxy/haproxy",
    fuzzer_entry_functions={
        "fuzz_cfg_parser": ["cfg_parse_listen"],
    },
    notes="Docker image not on GCR; must build locally",
))

_register(ProjectConfig(
    project="icu",
    preferred_backend="joern",
    repo_url="https://github.com/unicode-org/icu.git",
    fuzzer_entry_functions={
        "unicode_string_codepage_create_fuzzer": ["ucasemap_open", "ucasemap_close"],
    },
    notes="Large C++ project; fuzzer calls ICU C API",
))

_register(ProjectConfig(
    project="imagemagick",
    preferred_backend="joern",
    repo_url="https://github.com/ImageMagick/ImageMagick",
    fuzzer_entry_functions={
        "ping_fuzzer": ["PingBlob"],
    },
))

_register(ProjectConfig(
    project="libical",
    preferred_backend="joern",
    repo_url="https://github.com/libical/libical.git",
    fuzzer_entry_functions={
        "libicalvcard_fuzzer": ["icalparser_parse_string"],
        "libical_fuzzer": ["icalparser_parse_string"],
    },
))

_register(ProjectConfig(
    project="libjxl",
    preferred_backend="joern",
    repo_url="https://github.com/libjxl/libjxl.git",
    fuzzer_entry_functions={
        "color_encoding_fuzzer": ["JxlColorEncodingSetFromICCProfile"],
        "set_from_bytes_fuzzer": ["JxlDecoderSetInput"],
    },
))

_register(ProjectConfig(
    project="libplist",
    preferred_backend="joern",
    repo_url="https://github.com/libimobiledevice/libplist",
    fuzzer_entry_functions={
        "bplist_fuzzer": ["plist_from_bin"],
        "jplist_fuzzer": ["plist_from_json"],
        "oplist_fuzzer": ["plist_from_openstep"],
        "xplist_fuzzer": ["plist_from_xml"],
    },
))

_register(ProjectConfig(
    project="libxslt",
    preferred_backend="joern",
    repo_url="https://gitlab.gnome.org/GNOME/libxslt.git",
    fuzzer_entry_functions={
        "xpath": ["xsltFuzzXPath", "xsltFuzzXPathInit", "xsltFuzzXPathFreeObject"],
        "xslt": ["xsltFuzzXslt", "xsltFuzzXsltInit"],
    },
))

_register(ProjectConfig(
    project="llamacpp",
    preferred_backend="joern",
    repo_url="https://github.com/ggerganov/llama.cpp",
    fuzzer_entry_functions={
        "fuzz_json_to_grammar": ["json_schema_to_grammar"],
    },
))

_register(ProjectConfig(
    project="nettle",
    preferred_backend="joern",
    repo_url="https://git.lysator.liu.se/nettle/nettle",
    fuzzer_entry_functions={
        "fuzz_dsa_openssl_private_key_from_der": ["dsa_openssl_private_key_from_der_iterator"],
        "fuzz_dsa_sha1_keypair_from_sexp": ["dsa_sha1_keypair_from_sexp"],
        "fuzz_dsa_sha256_keypair_from_sexp": ["dsa_sha256_keypair_from_sexp"],
        "fuzz_rsa_keypair_from_der": ["rsa_public_key_init", "rsa_private_key_init", "rsa_keypair_from_der"],
        "fuzz_rsa_keypair_from_sexp": ["rsa_public_key_init", "rsa_private_key_init", "rsa_keypair_from_sexp"],
        "fuzz_rsa_public_key_from_der": ["rsa_public_key_init", "asn1_der_iterator_first", "rsa_public_key_from_der_iterator"],
    },
))

_register(ProjectConfig(
    project="opencv",
    preferred_backend="joern",
    repo_url="https://github.com/opencv/opencv.git",
    fuzzer_entry_functions={
        "imread_fuzzer": ["imread", "imdecode"],
    },
    notes="Huge project (78K functions); only parse modules/imgcodecs for speed",
))

_register(ProjectConfig(
    project="openexr",
    preferred_backend="joern",
    repo_url="https://github.com/AcademySoftwareFoundation/openexr",
    fuzzer_entry_functions={
        "openexr_exrcheck_fuzzer": ["exrcheck"],
    },
))

_register(ProjectConfig(
    project="openssh",
    preferred_backend="joern",
    repo_url="https://github.com/openssh/openssh-portable",
    fuzzer_entry_functions={
        "sntrup761_dec_fuzz": ["crypto_kem_sntrup761_dec"],
        "sntrup761_enc_fuzz": ["crypto_kem_sntrup761_enc"],
        "sshsig_fuzz": ["sshsig_dearmor"],
        "sshsigopt_fuzz": ["sshsigopt_parse"],
    },
))

_register(ProjectConfig(
    project="openssl",
    preferred_backend="joern",
    repo_url="https://github.com/openssl/openssl.git",
    fuzzer_entry_functions={
        "acert": ["FuzzerTestOneInput"],
        "asn1parse": ["FuzzerTestOneInput"],
        "cms": ["FuzzerTestOneInput"],
        "punycode": ["FuzzerTestOneInput"],
        "v3name": ["FuzzerTestOneInput"],
    },
    notes="OpenSSL uses FuzzerTestOneInput wrapper, not LLVMFuzzerTestOneInput directly",
))

_register(ProjectConfig(
    project="pugixml",
    preferred_backend="joern",
    repo_url="https://github.com/zeux/pugixml",
    fuzzer_entry_functions={
        "fuzz_parse": ["load_buffer"],
    },
))

_register(ProjectConfig(
    project="simdjson",
    preferred_backend="joern",
    repo_url="https://github.com/simdjson/simdjson.git",
    fuzzer_entry_functions={
        "fuzz_dump": ["parse"],
        "fuzz_parser": ["parse"],
    },
))

_register(ProjectConfig(
    project="wabt",
    preferred_backend="joern",
    repo_url="https://github.com/WebAssembly/wabt",
    fuzzer_entry_functions={
        "wasm2wat_fuzzer": ["ReadBinaryModule"],
    },
))

_register(ProjectConfig(
    project="yajl-ruby",
    preferred_backend="joern",
    repo_url="https://github.com/brianmario/yajl-ruby",
    fuzzer_entry_functions={
        "json_fuzzer": ["yajl_alloc", "yajl_parse", "yajl_free"],
    },
    notes="yajl C library is a git submodule; must clone recursively",
))

_register(ProjectConfig(
    project="zlib",
    preferred_backend="joern",
    repo_url="https://github.com/madler/zlib.git",
    fuzzer_entry_functions={
        "zlib_uncompress2_fuzzer": ["uncompress2"],
    },
))


def get_config(project: str) -> ProjectConfig | None:
    """Get analysis config for a project."""
    return CONFIGS.get(project)


def get_all_configs() -> dict[str, ProjectConfig]:
    """Get all project configs."""
    return dict(CONFIGS)
