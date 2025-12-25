"""Run command implementation"""

import os


# SAST benchmark divisions
SAST_DIVISIONS = {
    'owasp_python', 'owasp_python_curated',
    'owasp_java', 'owasp_java_curated',
    'juliet', 'juliet_curated',
    'issueblot', 'issueblot_curated',
    'secbench_js', 'secbench_js_curated',
}


def cmd_run(args, orchestrator):
    """Run benchmarks using the orchestrator"""

    # Check for --sast flag for SAST-only benchmarks
    run_sast = getattr(args, 'sast', False)

    # --curated: Run curated sample sets
    if args.curated:
        if run_sast:
            print("Running CURATED SAST benchmark sets")
            print("(OWASP Python + OWASP Java + Juliet + IssueBlot + SecBench.js)")
            print("=" * 80)

            # Run SAST curated sets
            orchestrator.run_owasp_python_division('owasp_python_curated', max_tests=args.max_tests)
            orchestrator.run_owasp_java_division('owasp_java_curated', max_tests=args.max_tests)
            orchestrator.run_juliet_division('juliet_curated', max_tests=args.max_tests)
            orchestrator.run_issueblot_division('issueblot_curated', max_tests=args.max_tests)
            orchestrator.run_secbench_js_division('secbench_js_curated', max_tests=args.max_tests)
        else:
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

        division = args.division.lower()

        # Check for SAST divisions first
        if 'owasp_python' in division:
            orchestrator.run_owasp_python_division(args.division, max_tests=args.max_tests)
        elif 'owasp_java' in division:
            orchestrator.run_owasp_java_division(args.division, max_tests=args.max_tests)
        elif 'juliet' in division:
            orchestrator.run_juliet_division(args.division, max_tests=args.max_tests)
        elif 'issueblot' in division:
            orchestrator.run_issueblot_division(args.division, max_tests=args.max_tests)
        elif 'secbench' in division:
            orchestrator.run_secbench_js_division(args.division, max_tests=args.max_tests)
        # SMT divisions
        elif args.division in ['slcomp_curated'] or \
           args.division.startswith('qf_sh') or args.division.startswith('qf_bsl') or \
           args.division.startswith('bsl_') or args.division.startswith('shid'):
            # SL-COMP divisions: qf_shid_entl, qf_shls_entl, qf_shlid_entl, qf_bsl_sat, etc.
            orchestrator.run_slcomp_division(args.division, max_tests=args.max_tests)
        elif 'qf_s' in division:
            # QF_S divisions (check after SL-COMP to avoid matching qf_shls, etc.)
            orchestrator.run_qf_s_division(args.division, max_tests=args.max_tests)
        elif 'qf_ax' in division:
            orchestrator.run_qf_ax_division(args.division, max_tests=args.max_tests)
        elif 'qf_bv' in division:
            orchestrator.run_qf_bv_division(args.division, max_tests=args.max_tests)
        else:
            print(f"ERROR: Unknown division '{args.division}'")
            print("\nAvailable SMT divisions:")
            print("  SL-COMP: qf_shid_entl, qf_shls_entl, slcomp_curated, etc.")
            print("  QF_S: qf_s_curated, qf_s_full")
            print("  QF_AX: qf_ax_curated, qf_ax_full")
            print("  QF_BV: qf_bv_curated, qf_bv_full")
            print("\nAvailable SAST divisions:")
            print("  Python: owasp_python, owasp_python_curated")
            print("  Java: owasp_java, owasp_java_curated")
            print("  C/C++: juliet, juliet_curated")
            print("  C#: issueblot, issueblot_curated")
            print("  JavaScript: secbench_js, secbench_js_curated")
            return

    # --all: Run ALL benchmarks (full suites)
    elif args.all:
        if run_sast:
            print("Running ALL SAST benchmark sets")
            print("(OWASP Python + OWASP Java + Juliet + IssueBlot + SecBench.js)")
            print("=" * 80)

            # Run all SAST benchmarks
            orchestrator.run_owasp_python_division('owasp_python', max_tests=args.max_tests)
            orchestrator.run_owasp_java_division('owasp_java', max_tests=args.max_tests)
            orchestrator.run_juliet_division('juliet', max_tests=args.max_tests)
            orchestrator.run_issueblot_division('issueblot', max_tests=args.max_tests)
            orchestrator.run_secbench_js_division('secbench_js', max_tests=args.max_tests)
        else:
            print("Running ALL SMT benchmark sets (~20k total: SL-COMP + QF_S + QF_AX + QF_BV)")
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

            # Run all QF_AX benchmarks
            orchestrator.run_qf_ax_division('qf_ax_full', max_tests=args.max_tests)

            # Run all QF_BV benchmarks
            orchestrator.run_qf_bv_division('qf_bv_full', max_tests=args.max_tests)

    orchestrator.print_summary()
    orchestrator.save_results(args.output)
