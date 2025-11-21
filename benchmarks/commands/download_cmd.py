"""Download command implementation"""


def cmd_download(args, orchestrator):
    """Download benchmarks using the orchestrator"""

    # --curated: Create curated sample sets
    if args.curated:
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
        print("=" * 80)
        print("DOWNLOADING ALL BENCHMARK SETS")
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
        print("ALL BENCHMARKS DOWNLOADED")
        print("=" * 80)

    # --division: Download specific division/suite
    elif args.division:
        if 'slcomp' in args.division.lower() or args.division.startswith('qf_sh') or \
           args.division.startswith('bsl') or args.division.startswith('shid'):
            count = orchestrator.download_slcomp_division(args.division, max_files=args.max_files)
            print(f"\nDownloaded {count} SL-COMP benchmarks")

        elif 'qf_ax' in args.division.lower():
            if 'full' in args.division or 'all' in args.division:
                count = orchestrator.download_qf_ax_full()
            else:
                count = orchestrator.download_qf_ax_samples(max_files=args.max_files)
            print(f"\nDownloaded {count} QF_AX benchmarks")

        elif 'qf_bv' in args.division.lower():
            if 'full' in args.division or 'all' in args.division:
                count = orchestrator.download_qf_bv_full()
            else:
                count = orchestrator.download_qf_bv_samples(max_files=args.max_files)
            print(f"\nDownloaded {count} QF_BV benchmarks")

        elif 'qf_s' in args.division.lower() or 'kaluza' in args.division.lower():
            if 'full' in args.division or 'all' in args.division:
                count = orchestrator.download_full_kaluza()
            else:
                count = orchestrator.download_qf_s_kaluza(max_files=args.max_files)
            print(f"\nDownloaded {count} QF_S benchmarks")

        else:
            print(f"ERROR: Unknown division '{args.division}'")
            print("\nAvailable options:")
            print("  --division slcomp")
            print("  --division qf_ax_full")
            print("  --division qf_bv_full")
            print("  --division qf_s_full")

    else:
        print("ERROR: Specify --all, --curated, or --division")
        print("\nExamples:")
        print("  python -m benchmarks download --all")
        print("  python -m benchmarks download --curated")
        print("  python -m benchmarks download --division qf_ax_full")
