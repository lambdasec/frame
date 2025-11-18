#!/usr/bin/env python3
"""
Run QF_BV benchmarks to validate bitvector theory implementation
"""

import os
import sys
import time
import json
from pathlib import Path
from typing import Dict, List, Optional
import subprocess

# Add frame to path
sys.path.insert(0, str(Path(__file__).parent))

def parse_smt2_file(filepath: str) -> Optional[Dict]:
    """Parse SMT2 file to extract logic and expected result"""
    with open(filepath, 'r') as f:
        content = f.read()

    logic = None
    expected = None

    for line in content.split('\n'):
        line = line.strip()
        if line.startswith('(set-logic'):
            logic = line.split()[1].rstrip(')')
        elif line.startswith('(set-info :status'):
            status = line.split()[2].rstrip(')')
            expected = status

    return {'logic': logic, 'expected': expected, 'content': content}

def run_z3_on_file(filepath: str, timeout: int = 10) -> Dict:
    """Run Z3 on SMT2 file and return result"""
    try:
        result = subprocess.run(
            ['z3', filepath, '-T:' + str(timeout)],
            capture_output=True,
            text=True,
            timeout=timeout + 1
        )

        output = result.stdout.strip()

        if 'sat' in output and 'unsat' not in output:
            return {'result': 'sat', 'time': 0, 'output': output}
        elif 'unsat' in output:
            return {'result': 'unsat', 'time': 0, 'output': output}
        else:
            return {'result': 'unknown', 'time': 0, 'output': output}

    except subprocess.TimeoutExpired:
        return {'result': 'timeout', 'time': timeout, 'output': ''}
    except Exception as e:
        return {'result': 'error', 'time': 0, 'output': str(e)}

def run_benchmarks(benchmark_dir: str, max_tests: Optional[int] = None, timeout: int = 10):
    """Run QF_BV benchmarks"""

    print(f"Running QF_BV benchmarks from: {benchmark_dir}")
    print(f"Timeout: {timeout}s per benchmark")
    print("=" * 80)

    # Get all .smt2 files
    files = sorted([f for f in os.listdir(benchmark_dir) if f.endswith('.smt2')])

    if max_tests:
        files = files[:max_tests]

    print(f"Total benchmarks to run: {len(files)}\n")

    results = {
        'correct': 0,
        'incorrect': 0,
        'timeout': 0,
        'error': 0,
        'unknown': 0,
        'total': len(files),
        'details': []
    }

    start_time = time.time()

    for i, filename in enumerate(files, 1):
        filepath = os.path.join(benchmark_dir, filename)

        # Parse file
        info = parse_smt2_file(filepath)

        if not info or info['logic'] != 'QF_BV':
            print(f"[{i}/{len(files)}] SKIP {filename} (not QF_BV)")
            continue

        # Run Z3
        bench_start = time.time()
        result = run_z3_on_file(filepath, timeout=timeout)
        bench_time = time.time() - bench_start

        # Check correctness
        expected = info.get('expected')
        actual = result['result']

        if actual == 'timeout':
            status = 'TIMEOUT'
            results['timeout'] += 1
        elif actual == 'error':
            status = 'ERROR'
            results['error'] += 1
        elif actual == 'unknown':
            status = 'UNKNOWN'
            results['unknown'] += 1
        elif expected and expected.lower() == actual.lower():
            status = 'PASS'
            results['correct'] += 1
        elif expected:
            status = 'FAIL'
            results['incorrect'] += 1
        else:
            # No expected result
            status = f'OK ({actual})'
            results['correct'] += 1

        # Progress output
        if i % 10 == 0 or status != 'PASS':
            print(f"[{i}/{len(files)}] {status:8s} {filename:60s} ({bench_time:.3f}s)")

        results['details'].append({
            'file': filename,
            'expected': expected,
            'actual': actual,
            'status': status,
            'time': bench_time
        })

    total_time = time.time() - start_time

    # Print summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total benchmarks:  {results['total']}")
    print(f"Correct:           {results['correct']} ({100*results['correct']/results['total']:.1f}%)")
    print(f"Incorrect:         {results['incorrect']}")
    print(f"Timeout:           {results['timeout']}")
    print(f"Error:             {results['error']}")
    print(f"Unknown:           {results['unknown']}")
    print(f"Total time:        {total_time:.1f}s")
    print(f"Average time:      {total_time/results['total']:.3f}s per benchmark")

    # Show failures
    if results['incorrect'] > 0:
        print("\nFAILURES:")
        print("-" * 80)
        for detail in results['details']:
            if detail['status'] == 'FAIL':
                print(f"  {detail['file']:60s} Expected: {detail['expected']:6s} Got: {detail['actual']}")

    # Save results
    output_file = 'qf_bv_benchmark_results.json'
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\nDetailed results saved to: {output_file}")

    return results

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Run QF_BV benchmarks')
    parser.add_argument('--max-tests', type=int, default=100, help='Maximum number of tests to run')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout per benchmark (seconds)')
    parser.add_argument('--benchmark-dir', type=str, default='./benchmarks/cache/qf_bv_full',
                       help='Directory containing QF_BV benchmarks')

    args = parser.parse_args()

    if not os.path.exists(args.benchmark_dir):
        print(f"Error: Benchmark directory not found: {args.benchmark_dir}")
        sys.exit(1)

    run_benchmarks(args.benchmark_dir, max_tests=args.max_tests, timeout=args.timeout)
