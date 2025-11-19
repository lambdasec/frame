"""Run command implementation"""

import os


def cmd_run(args, orchestrator):
    """Run benchmarks using the orchestrator"""

    # --curated: Run curated sample sets (~4000-5000 benchmarks)
    if args.curated:
        print("Running CURATED benchmark sets (~4000+ total: 700 SL-COMP + 3300 QF_S + QF_AX + QF_BV)")
        print("(QF_AX and QF_BV counts depend on available full benchmarks from SMT-LIB 2024)")
        print("=" * 80)

        # Ensure curated sets exist
        slcomp_curated_dir = os.path.join(args.cache_dir, 'slcomp_curated')
        qf_s_curated_dir = os.path.join(args.cache_dir, 'qf_s', 'qf_s_curated')
        qf_ax_curated_dir = os.path.join(args.cache_dir, 'qf_ax', 'qf_ax_curated')
        qf_bv_curated_dir = os.path.join(args.cache_dir, 'qf_bv', 'qf_bv_curated')

        if not os.path.exists(slcomp_curated_dir):
            print("\nSL-COMP curated set not found. Creating...")
            orchestrator.create_slcomp_curated_set()

        if not os.path.exists(qf_s_curated_dir):
            print("\nQF_S curated set not found. Creating...")
            orchestrator.create_qf_s_curated_set()

        if not os.path.exists(qf_ax_curated_dir):
            print("\nQF_AX curated set not found. Creating...")
            orchestrator.create_qf_ax_curated_set()

        if not os.path.exists(qf_bv_curated_dir):
            print("\nQF_BV curated set not found. Creating...")
            orchestrator.create_qf_bv_curated_set()

        # Run all curated sets
        orchestrator.run_slcomp_division('slcomp_curated', max_tests=args.max_tests)
        orchestrator.run_qf_s_division('qf_s_curated', max_tests=args.max_tests)
        orchestrator.run_qf_ax_division('qf_ax_curated', max_tests=args.max_tests)
        orchestrator.run_qf_bv_division('qf_bv_curated', max_tests=args.max_tests)

    # --division: Run specific division
    elif args.division:
        print(f"Running specific division: {args.division}")
        print("=" * 80)

        # Determine division type
        if 'qf_s' in args.division.lower():
            orchestrator.run_qf_s_division(args.division, max_tests=args.max_tests)
        elif 'qf_ax' in args.division.lower():
            orchestrator.run_qf_ax_division(args.division, max_tests=args.max_tests)
        elif 'qf_bv' in args.division.lower():
            orchestrator.run_qf_bv_division(args.division, max_tests=args.max_tests)
        elif args.division in ['slcomp_curated'] or args.division.startswith('qf_') or \
             args.division.startswith('bsl_') or args.division.startswith('shid'):
            orchestrator.run_slcomp_division(args.division, max_tests=args.max_tests)
        else:
            print(f"ERROR: Unknown division '{args.division}'")
            print("Available divisions:")
            print("  SL-COMP: qf_shid_entl, qf_shls_entl, qf_bsl_sat, etc.")
            print("  QF_S: qf_s_curated, or subdirectories in qf_s_full/")
            print("  QF_AX: qf_ax_curated, samples")
            print("  QF_BV: qf_bv_curated, samples")
            return

    # --all: Run ALL benchmarks (full suites, ~20k total)
    elif args.all:
        print("Running ALL benchmark sets (~20k total: SL-COMP + QF_S)")
        print("=" * 80)

        # All 12 SL-COMP divisions
        slcomp_divisions = [
            'qf_shid_entl', 'qf_shls_entl', 'qf_shlid_entl',
            'qf_shidlia_entl', 'shid_entl', 'shidlia_entl',
            'qf_bsl_sat', 'qf_bsllia_sat', 'bsl_sat',
            'qf_shid_sat', 'qf_shidlia_sat', 'qf_shls_sat',
        ]

        # Run all SL-COMP divisions
        for division in slcomp_divisions:
            orchestrator.run_slcomp_division(division, max_tests=args.max_tests)

        # Run all QF_S benchmarks
        orchestrator.run_qf_s_division('qf_s_full', max_tests=args.max_tests)

    orchestrator.print_summary()
    orchestrator.save_results(args.output)
