# Z-Code-Analyzer Batch Results — 46 Projects

**成功: 43/46 | 失败: 3 | 总函数: 140,295 | 总边: 321,494**

| # | Project | Status | Functions | Edges | Build(s) | SVF(s) | Total(s) | Detected Fuzzers | Benchmark Cases | Reachability |
|---|---------|--------|-----------|-------|----------|--------|----------|-----------------|-----------------|--------------|
| 1 | apache-httpd | OK | 6,270 | 15,326 | 112 | 373 | 488 | 7 | 2 | fuzz_addr_parse=8, fuzz_tokenize=8 |
| 2 | arrow | OK | 20,266 | 40,626 | 1925 | 163 | 2096 | 80 | 4 | csv_fuzz=0, ipc_file_fuzz=0, ipc_stream_fuzz=0, ipc_tensor_stream_fuzz=0 |
| 3 | bad_example | OK | 188 | 155 | 30 | 1 | 59 | 1 | 1 | bad_example_fuzzer=0 |
| 4 | binutils | FAIL | 0 | 0 | 0 | 0 | 1247 | 0 | 2 | N/A |
| 5 | boost | OK | 97 | 10 | 36 | 1 | 37 | 58 | 5 | boost_graph_graphviz_fuzzer=0, boost_ptree_inforead_fuzzer=0, boost_ptree_iniread_fuzzer=0, boost_ptree_jsonread_fuzzer=0, boost_ptree_xmlread_fuzzer=0 |
| 6 | brotli | OK | 258 | 186 | 31 | 4 | 35 | 1 | 1 | decode_fuzzer=8 |
| 7 | clamav | OK | 148 | 41 | 107 | 1 | 109 | 4 | 1 | clamav_scanmap_fuzzer=0 |
| 8 | curl | OK | 2 | 0 | 22 | 1 | 24 | 6 | 1 | fuzz_url=0 |
| 9 | draco | OK | 3 | 0 | 26 | 1 | 27 | 4 | 3 | draco_mesh_decoder_fuzzer=0, draco_mesh_decoder_without_dequantization_fuzzer=0, draco_pc_decoder_fuzzer=0 |
| 10 | easywsclient | OK | 2 | 0 | 22 | 1 | 24 | 1 | 1 | easyws_fuzzer=0 |
| 11 | fftw3 | OK | 1,712 | 2,438 | 195 | 20 | 216 | 1 | 1 | fftw3_fuzzer=14 |
| 12 | flatbuffers | OK | 3 | 0 | 23 | 1 | 24 | 10 | 2 | flatbuffers_annotator_fuzzer=0, flatbuffers_verifier_fuzzer=0 |
| 13 | flex | OK | 5 | 0 | 49 | 1 | 50 | 2 | 1 | (no data) |
| 14 | freerdp | OK | 10,710 | 37,757 | 305 | 179 | 488 | 7 | 4 | TestFuzzCommonAssistanceBinToHexString=2, TestFuzzCommonAssistanceHexStringToBin=4, TestFuzzCommonAssistanceParseFileBuffer=222, TestFuzzCryptoCertificateDataSetPEM=9 |
| 15 | gdal | FAIL | 0 | 0 | 2002 | 0 | 2142 | 0 | 4 | N/A |
| 16 | glslang | OK | 2 | 0 | 24 | 1 | 25 | 1 | 1 | compile_fuzzer=0 |
| 17 | haproxy | FAIL | 0 | 0 | 98 | 0 | 120 | 0 | 1 | N/A |
| 18 | hwloc | OK | 1,002 | 1,328 | 60 | 8 | 69 | 1 | 1 | hwloc_fuzzer=3 |
| 19 | icu | OK | 3 | 0 | 38 | 1 | 39 | 34 | 1 | unicode_string_codepage_create_fuzzer=0 |
| 20 | imagemagick | OK | 8,020 | 19,699 | 194 | 78 | 274 | 55 | 1 | ping_fuzzer=7 |
| 21 | iperf | OK | 589 | 474 | 33 | 2 | 35 | 2 | 1 | cjson_fuzzer=5 |
| 22 | jq | OK | 1,744 | 5,675 | 63 | 10 | 74 | 11 | 2 | jq_fuzz_parse=32, jq_fuzz_parse_extended=5 |
| 23 | libcoap | OK | 1,201 | 2,215 | 40 | 5 | 45 | 11 | 3 | get_asn1_tag_target=6, oscore_conf_parse_target=16, split_uri_target=8 |
| 24 | libgit2 | OK | 11,156 | 39,192 | 1770 | 157 | 1931 | 8 | 2 | objects_fuzzer=19, patch_parse_fuzzer=2 |
| 25 | libical | OK | 2,430 | 7,025 | 63 | 5 | 70 | 3 | 2 | libicalvcard_fuzzer=0, libical_fuzzer=19 |
| 26 | libjxl | OK | 4,701 | 5,915 | 124 | 386 | 511 | 24 | 2 | color_encoding_fuzzer=0, set_from_bytes_fuzzer=0 |
| 27 | libpcap | OK | 696 | 631 | 42 | 2 | 44 | 3 | 1 | fuzz_filter=10 |
| 28 | libplist | OK | 30 | 18 | 38 | 1 | 39 | 4 | 4 | bplist_fuzzer=0, jplist_fuzzer=0, oplist_fuzzer=0, xplist_fuzzer=0 |
| 29 | libxslt | OK | 871 | 605 | 46 | 2 | 48 | 13 | 2 | xpath=0, xslt=0 |
| 30 | libyaml | OK | 214 | 277 | 36 | 2 | 38 | 9 | 2 | libyaml_loader_fuzzer=9, libyaml_scanner_fuzzer=7 |
| 31 | llamacpp | OK | 604 | 643 | 36 | 2 | 38 | 8 | 1 | fuzz_json_to_grammar=0 |
| 32 | mbedtls | OK | 2,950 | 5,029 | 46 | 9 | 56 | 10 | 4 | fuzz_pkcs7=59, fuzz_x509crl=41, fuzz_x509crt=72, fuzz_x509csr=83 |
| 33 | ndpi | OK | 3,269 | 4,546 | 64 | 17 | 82 | 51 | 7 | fuzz_filecfg_categories=52, fuzz_filecfg_category=51, fuzz_filecfg_config=49, fuzz_filecfg_malicious_ja4=51, fuzz_filecfg_malicious_sha1=9, fuzz_filecfg_protocols=51, fuzz_filecfg_risk_domains=50 |
| 34 | nettle | OK | 1,235 | 1,830 | 40 | 3 | 44 | 7 | 6 | fuzz_dsa_openssl_private_key_from_der=2, fuzz_dsa_sha1_keypair_from_sexp=2, fuzz_dsa_sha256_keypair_from_sexp=2, fuzz_rsa_keypair_from_der=0, fuzz_rsa_keypair_from_sexp=0, fuzz_rsa_public_key_from_der=0 |
| 35 | opencv | OK | 2,194 | 3,211 | 94 | 12 | 106 | 9 | 1 | imread_fuzzer=0 |
| 36 | openexr | OK | 9 | 0 | 27 | 1 | 28 | 2 | 1 | openexr_exrcheck_fuzzer=0 |
| 37 | openssh | OK | 2,133 | 2,650 | 115 | 5 | 120 | 11 | 4 | sntrup761_dec_fuzz=0, sntrup761_enc_fuzz=0, sshsig_fuzz=46, sshsigopt_fuzz=0 |
| 38 | openssl | OK | 20,689 | 41,323 | 11940 | 260 | 12204 | 1 | 5 | acert=0, asn1parse=0, cms=0, punycode=0, v3name=0 |
| 39 | php | OK | 17,746 | 31,002 | 4844 | 114 | 4961 | 10 | 2 | fuzzer-json=48, fuzzer-unserialize=99 |
| 40 | pjsip | OK | 8,608 | 33,615 | 100 | 302 | 406 | 25 | 1 | fuzz-dns=34 |
| 41 | pugixml | OK | 2 | 0 | 21 | 1 | 23 | 2 | 1 | fuzz_parse=0 |
| 42 | simdjson | OK | 4 | 0 | 28 | 1 | 29 | 15 | 2 | fuzz_dump=0, fuzz_parser=0 |
| 43 | strongswan | OK | 8,345 | 17,899 | 118 | 119 | 239 | 9 | 2 | fuzz_crls=5, fuzz_ids=6 |
| 44 | wabt | OK | 2 | 0 | 26 | 1 | 27 | 6 | 1 | wasm2wat_fuzzer=0 |
| 45 | yajl-ruby | OK | 2 | 0 | 21 | 1 | 22 | 1 | 1 | json_fuzzer=0 |
| 46 | zlib | OK | 180 | 153 | 20 | 1 | 21 | 11 | 1 | zlib_uncompress2_fuzzer=0 |
