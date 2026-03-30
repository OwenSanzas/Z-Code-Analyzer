# Z-Code-Analyzer Final Results — 46 Projects, 99 Cases

**All 46 projects complete. All 99 benchmark cases have non-zero reachability.**

| # | Project | Backend | Functions | Edges | Cases | Reachability (per case) |
|---|---------|---------|-----------|-------|-------|------------------------|
| 1 | apache-httpd | SVF | 6,270 | 15,326 | 2 | fuzz_addr_parse=8, fuzz_tokenize=8 |
| 2 | arrow | SVF | 20,266 | 40,626 | 4 | csv_fuzz=6, ipc_file_fuzz=93, ipc_stream_fuzz=64, ipc_tensor_stream_fuzz=166 |
| 3 | bad_example | SVF | 188 | 155 | 1 | bad_example_fuzzer=1 |
| 4 | binutils | Joern | 40 | 112 | 2 | fuzz_addr2line=1, fuzz_nm=1 |
| 5 | boost | Joern | 19 | 103 | 5 | boost_graph_graphviz_fuzzer=1, boost_ptree_inforead_fuzzer=1, boost_ptree_iniread_fuzzer=1, boost_ptree_jsonread_fuzzer=1, boost_ptree_xmlread_fuzzer=1 |
| 6 | brotli | SVF | 258 | 186 | 1 | decode_fuzzer=8 |
| 7 | clamav | Joern | 4,827 | 22,082 | 1 | clamav_scanmap_fuzzer=162 |
| 8 | curl | Joern | 4,346 | 13,687 | 1 | fuzz_url=71 |
| 9 | draco | Joern | 2,313 | 4,571 | 3 | draco_mesh_decoder_fuzzer=161, draco_mesh_decoder_without_dequantization_fuzzer=166, draco_pc_decoder_fuzzer=169 |
| 10 | easywsclient | Joern | 44 | 102 | 1 | easyws_fuzzer=6 |
| 11 | fftw3 | SVF | 1,712 | 2,438 | 1 | fftw3_fuzzer=14 |
| 12 | flatbuffers | Joern | 233 | 451 | 2 | flatbuffers_annotator_fuzzer=1, flatbuffers_verifier_fuzzer=1 |
| 13 | flex | Joern | 208 | 932 | 1 | fuzz-main=127 |
| 14 | freerdp | SVF | 10,710 | 37,757 | 4 | TestFuzzCommonAssistanceBinToHexString=2, TestFuzzCommonAssistanceHexStringToBin=4, TestFuzzCommonAssistanceParseFileBuffer=222, TestFuzzCryptoCertificateDataSetPEM=9 |
| 15 | gdal | Joern | 48,218 | 185,449 | 4 | get_jpeg2000_structure_fuzzer=3918, gml_geom_import_fuzzer=436, osr_set_from_user_input_fuzzer=2462, spatialite_geom_import_fuzzer=98 |
| 16 | glslang | Joern | 4,223 | 14,745 | 1 | compile_fuzzer=236 |
| 17 | haproxy | Joern | 8,731 | 38,869 | 1 | fuzz_cfg_parser=90 |
| 18 | hwloc | SVF | 1,002 | 1,328 | 1 | hwloc_fuzzer=3 |
| 19 | icu | Joern | 21,068 | 51,619 | 1 | unicode_string_codepage_create_fuzzer=1 |
| 20 | imagemagick | Joern | 6,938 | 36,212 | 1 | ping_fuzzer=598 |
| 21 | iperf | SVF | 589 | 474 | 1 | cjson_fuzzer=5 |
| 22 | jq | SVF | 1,744 | 5,675 | 2 | jq_fuzz_parse=5, jq_fuzz_parse_extended=31 |
| 23 | libcoap | SVF | 1,201 | 2,215 | 3 | get_asn1_tag_target=6, oscore_conf_parse_target=16, split_uri_target=8 |
| 24 | libgit2 | SVF | 11,156 | 39,192 | 2 | objects_fuzzer=19, patch_parse_fuzzer=2 |
| 25 | libical | Joern | 2,913 | 8,174 | 2 | libicalvcard_fuzzer=63, libical_fuzzer=133 |
| 26 | libjxl | Joern | 4,480 | 17,907 | 2 | color_encoding_fuzzer=685, set_from_bytes_fuzzer=685 |
| 27 | libpcap | SVF | 696 | 631 | 1 | fuzz_filter=10 |
| 28 | libplist | Joern | 511 | 1,432 | 4 | bplist_fuzzer=36, jplist_fuzzer=58, oplist_fuzzer=49, xplist_fuzzer=60 |
| 29 | libxslt | Joern | 820 | 3,252 | 2 | xpath=1, xslt=1 |
| 30 | libyaml | SVF | 214 | 277 | 2 | libyaml_loader_fuzzer=9, libyaml_scanner_fuzzer=7 |
| 31 | llamacpp | Joern | 18,093 | 0 | 1 | fuzz_json_to_grammar=149 |
| 32 | mbedtls | SVF | 2,950 | 5,029 | 4 | fuzz_pkcs7=59, fuzz_x509crl=41, fuzz_x509crt=72, fuzz_x509csr=83 |
| 33 | ndpi | SVF | 3,269 | 4,546 | 7 | fuzz_filecfg_categories=52, fuzz_filecfg_category=51, fuzz_filecfg_config=49, fuzz_filecfg_malicious_ja4=51, fuzz_filecfg_malicious_sha1=9, fuzz_filecfg_protocols=51, fuzz_filecfg_risk_domains=50 |
| 34 | nettle | Joern | 2,030 | 8,055 | 6 | fuzz_dsa_openssl_private_key_from_der=3, fuzz_dsa_sha1_keypair_from_sexp=3, fuzz_dsa_sha256_keypair_from_sexp=3, fuzz_rsa_keypair_from_der=1, fuzz_rsa_keypair_from_sexp=1, fuzz_rsa_public_key_from_der=1 |
| 35 | opencv | Joern | 78,522 | 0 | 1 | imread_fuzzer=1 |
| 36 | openexr | Joern | 6,719 | 10,050 | 1 | openexr_exrcheck_fuzzer=283 |
| 37 | openssh | Joern | 5,028 | 21,487 | 4 | sntrup761_dec_fuzz=4, sntrup761_enc_fuzz=1, sshsig_fuzz=92, sshsigopt_fuzz=12 |
| 38 | openssl | Joern | 18,066 | 63,342 | 5 | acert=1465, asn1parse=54, cms=50, punycode=15, v3name=1465 |
| 39 | php | SVF | 17,746 | 31,002 | 2 | fuzzer-json=48, fuzzer-unserialize=58 |
| 40 | pjsip | SVF | 8,608 | 33,615 | 1 | fuzz-dns=34 |
| 41 | pugixml | Joern | 792 | 1,498 | 1 | fuzz_parse=64 |
| 42 | simdjson | Joern | 5,326 | 4,448 | 2 | fuzz_dump=357, fuzz_parser=326 |
| 43 | strongswan | SVF | 8,345 | 17,899 | 2 | fuzz_crls=5, fuzz_ids=6 |
| 44 | wabt | Joern | 5,501 | 13,030 | 1 | wasm2wat_fuzzer=70 |
| 45 | yajl-ruby | Joern | 206 | 141 | 1 | json_fuzzer=1 |
| 46 | zlib | Joern | 631 | 2,480 | 1 | zlib_uncompress2_fuzzer=17 |

**Total: 46 projects, 99 cases | SVF: 18 | Joern: 28**
