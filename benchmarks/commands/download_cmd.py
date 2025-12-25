"""Download command implementation"""


def cmd_download(args, orchestrator):
    """Download benchmarks using the orchestrator"""

    # Check for --sast flag
    download_sast = getattr(args, 'sast', False)

    # --curated: Create curated sample sets
    if args.curated:
        if download_sast:
            print("=" * 80)
            print("CREATING CURATED SAST BENCHMARK SETS")
            print("=" * 80)
            print("This will create curated sample sets from SAST benchmarks")
            print()

            # Create SAST curated sets
            owasp_py_count = orchestrator.create_owasp_python_curated_set()
            owasp_java_count = orchestrator.create_owasp_java_curated_set()
            juliet_count = orchestrator.create_juliet_curated_set()
            issueblot_count = orchestrator.create_issueblot_curated_set()
            secbench_count = orchestrator.create_secbench_js_curated_set()

            total = owasp_py_count + owasp_java_count + juliet_count + issueblot_count + secbench_count
            print("\n" + "=" * 80)
            print("CURATED SAST SETS CREATED")
            print("=" * 80)
            print(f"\nTotal curated SAST benchmarks: {total}")
            print(f"  - OWASP Python curated: {owasp_py_count} tests")
            print(f"  - OWASP Java curated: {owasp_java_count} tests")
            print(f"  - Juliet C/C++ curated: {juliet_count} tests")
            print(f"  - IssueBlot.NET curated: {issueblot_count} tests")
            print(f"  - SecBench.js curated: {secbench_count} tests")
            print("\nTo run curated SAST benchmarks:")
            print("  python -m benchmarks run --curated --sast")
        else:
            print("=" * 80)
            print("CREATING CURATED BENCHMARK SETS")
            print("=" * 80)
            print("This will create curated sample sets from available benchmarks")
            print()

            # Create all curated sets
            slcomp_count = orchestrator.create_slcomp_curated_set()
            qf_s_count = orchestrator.create_qf_s_curated_set()
            qf_ax_count = orchestrator.create_qf_ax_curated_set()
            qf_bv_count = orchestrator.create_qf_bv_curated_set()

            print("\n" + "=" * 80)
            print("CURATED SETS CREATED")
            print("=" * 80)
            print(f"\nTotal curated benchmarks: {slcomp_count + qf_s_count + qf_ax_count + qf_bv_count}")
            print(f"  - SL-COMP curated: {slcomp_count} tests")
            print(f"  - QF_S curated: {qf_s_count} tests")
            print(f"  - QF_AX curated: {qf_ax_count} tests")
            print(f"  - QF_BV curated: {qf_bv_count} tests")
            print("\nTo run curated benchmarks:")
            print("  python -m benchmarks run --curated")

    # --all: Download all full benchmark sets
    elif args.all:
        if download_sast:
            print("=" * 80)
            print("DOWNLOADING ALL SAST BENCHMARK SETS")
            print("=" * 80)
            print("This will download full SAST benchmark sets from official sources")
            print("  - OWASP BenchmarkPython (~2700 tests)")
            print("  - OWASP BenchmarkJava (~2700 tests)")
            print("  - Juliet C/C++ Test Suite (~57000 tests)")
            print("  - IssueBlot.NET C# (~200 tests)")
            print("  - SecBench.js JavaScript (~500 tests)")
            print()

            # Download all SAST benchmarks
            owasp_py_count = orchestrator.download_owasp_python()
            owasp_java_count = orchestrator.download_owasp_java()
            juliet_count = orchestrator.download_juliet()
            issueblot_count = orchestrator.download_issueblot()
            secbench_count = orchestrator.download_secbench_js()

            total = owasp_py_count + owasp_java_count + juliet_count + issueblot_count + secbench_count
            print("\n" + "=" * 80)
            print("ALL SAST BENCHMARKS DOWNLOADED")
            print("=" * 80)
            print(f"\nTotal SAST benchmarks: {total}")
            print(f"  - OWASP Python: {owasp_py_count} tests")
            print(f"  - OWASP Java: {owasp_java_count} tests")
            print(f"  - Juliet C/C++: {juliet_count} tests")
            print(f"  - IssueBlot.NET: {issueblot_count} tests")
            print(f"  - SecBench.js: {secbench_count} tests")
        else:
            print("=" * 80)
            print("DOWNLOADING ALL SMT BENCHMARK SETS")
            print("=" * 80)
            print("This will download full benchmark sets from official sources")
            print("  - SL-COMP benchmarks (~1300 tests)")
            print("  - QF_S Full Set (SMT-LIB 2024)")
            print("  - QF_AX Full Set (SMT-LIB 2024)")
            print("  - QF_BV Full Set (SMT-LIB 2024)")
            print()

            # Download all full sets
            orchestrator.download_full_kaluza()
            qf_ax_count = orchestrator.download_qf_ax_full()
            qf_bv_count = orchestrator.download_qf_bv_full()

            print("\n" + "=" * 80)
            print("ALL SMT BENCHMARKS DOWNLOADED")
            print("=" * 80)

    # --division: Download specific division/suite
    elif args.division:
        division = args.division.lower()

        # SAST divisions
        if 'owasp_python' in division:
            count = orchestrator.download_owasp_python(max_files=args.max_files)
            print(f"\nDownloaded {count} OWASP Python benchmarks")

        elif 'owasp_java' in division:
            count = orchestrator.download_owasp_java(max_files=args.max_files)
            print(f"\nDownloaded {count} OWASP Java benchmarks")

        elif 'juliet' in division:
            count = orchestrator.download_juliet(max_files=args.max_files)
            print(f"\nDownloaded {count} Juliet C/C++ benchmarks")

        elif 'issueblot' in division:
            count = orchestrator.download_issueblot(max_files=args.max_files)
            print(f"\nDownloaded {count} IssueBlot.NET benchmarks")

        elif 'secbench' in division:
            count = orchestrator.download_secbench_js(max_files=args.max_files)
            print(f"\nDownloaded {count} SecBench.js benchmarks")

        # SMT divisions
        elif 'slcomp' in division or args.division.startswith('qf_sh') or \
           args.division.startswith('bsl') or args.division.startswith('shid'):
            count = orchestrator.download_slcomp_division(args.division, max_files=args.max_files)
            print(f"\nDownloaded {count} SL-COMP benchmarks")

        elif 'qf_ax' in division:
            if 'full' in division or 'all' in division:
                count = orchestrator.download_qf_ax_full()
            else:
                count = orchestrator.download_qf_ax_samples(max_files=args.max_files)
            print(f"\nDownloaded {count} QF_AX benchmarks")

        elif 'qf_bv' in division:
            if 'full' in division or 'all' in division:
                count = orchestrator.download_qf_bv_full()
            else:
                count = orchestrator.download_qf_bv_samples(max_files=args.max_files)
            print(f"\nDownloaded {count} QF_BV benchmarks")

        elif 'qf_s' in division or 'kaluza' in division:
            if 'full' in division or 'all' in division:
                count = orchestrator.download_full_kaluza()
            else:
                count = orchestrator.download_qf_s_kaluza(max_files=args.max_files)
            print(f"\nDownloaded {count} QF_S benchmarks")

        else:
            print(f"ERROR: Unknown division '{args.division}'")
            print("\nAvailable SMT options:")
            print("  --division slcomp")
            print("  --division qf_ax_full")
            print("  --division qf_bv_full")
            print("  --division qf_s_full")
            print("\nAvailable SAST options:")
            print("  --division owasp_python")
            print("  --division owasp_java")
            print("  --division juliet")
            print("  --division issueblot")
            print("  --division secbench_js")

    else:
        print("ERROR: Specify --all, --curated, or --division")
        print("\nSMT Examples:")
        print("  python -m benchmarks download --all")
        print("  python -m benchmarks download --curated")
        print("  python -m benchmarks download --division qf_ax_full")
        print("\nSAST Examples:")
        print("  python -m benchmarks download --all --sast")
        print("  python -m benchmarks download --curated --sast")
        print("  python -m benchmarks download --division owasp_python")
