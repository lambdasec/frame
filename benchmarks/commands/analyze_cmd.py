"""Analyze command implementation"""

import json
import os


def cmd_analyze(args):
    """Analyze benchmark results"""

    results_file = os.path.join(args.cache_dir, 'benchmark_results.json')

    if not os.path.exists(results_file):
        print(f"ERROR: No results found at {results_file}")
        print("Run benchmarks first with: python -m benchmarks run --curated")
        return

    # Load results
    with open(results_file, 'r') as f:
        results_data = json.load(f)

    print(f"\nLoaded {len(results_data)} benchmark results from {results_file}")

    # Analyze by failure type
    if args.failures:
        print("\n" + "=" * 80)
        print("FAILURE ANALYSIS")
        print("=" * 80)

        failures = [r for r in results_data if r['expected'] != r['actual'] or r.get('error')]

        if not failures:
            print("\n✅ No failures found! All benchmarks passed.")
            return

        print(f"\nTotal failures: {len(failures)}/{len(results_data)} ({len(failures)/len(results_data)*100:.1f}%)")

        # Group by error type
        by_error = {}
        for failure in failures:
            error = failure.get('error') or 'incorrect_result'
            if error not in by_error:
                by_error[error] = []
            by_error[error].append(failure)

        print("\nFailures by type:")
        for error_type, cases in sorted(by_error.items(), key=lambda x: -len(x[1])):
            print(f"  {error_type}: {len(cases)} cases")
            for case in cases[:5]:  # Show first 5
                print(f"    - {case['division']}/{case['filename']}: "
                      f"expected={case['expected']}, got={case['actual']}")
            if len(cases) > 5:
                print(f"    ... and {len(cases) - 5} more")
            print()

    else:
        # General analysis
        print("\n" + "=" * 80)
        print("RESULTS SUMMARY")
        print("=" * 80)

        total = len(results_data)
        correct = sum(1 for r in results_data if r['expected'] == r['actual'] and not r.get('error'))
        errors = sum(1 for r in results_data if r.get('error'))

        print(f"\nOverall:")
        print(f"  Total:     {total}")
        print(f"  Correct:   {correct} ({correct/total*100:.1f}%)")
        print(f"  Incorrect: {total - correct - errors}")
        print(f"  Errors:    {errors}")

        # By suite
        by_suite = {}
        for r in results_data:
            suite = r['suite']
            if suite not in by_suite:
                by_suite[suite] = {'total': 0, 'correct': 0, 'errors': 0}
            by_suite[suite]['total'] += 1
            if r['expected'] == r['actual'] and not r.get('error'):
                by_suite[suite]['correct'] += 1
            if r.get('error'):
                by_suite[suite]['errors'] += 1

        print(f"\nBy Suite:")
        for suite, stats in sorted(by_suite.items()):
            total = stats['total']
            correct = stats['correct']
            errors = stats['errors']
            print(f"  {suite}:")
            print(f"    Total: {total}, Correct: {correct} ({correct/total*100:.1f}%), Errors: {errors}")
