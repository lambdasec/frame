"""
Regression tests for refactored benchmark modules

This test file ensures that the benchmark refactoring maintains
backward compatibility and all modules work correctly together.
"""

import pytest
import os
import tempfile
import shutil
from pathlib import Path


class TestBenchmarkCore:
    """Test core benchmark modules (result, base_runner, analysis)"""

    def test_benchmark_result_creation(self):
        """Test BenchmarkResult dataclass"""
        from benchmarks.core import BenchmarkResult

        result = BenchmarkResult(
            filename="test.smt2",
            suite="qf_ax",
            division="samples",
            expected="sat",
            actual="sat",
            time_ms=10.5
        )

        assert result.filename == "test.smt2"
        assert result.correct is True
        assert result.error is None

    def test_benchmark_result_incorrect(self):
        """Test incorrect result"""
        from benchmarks.core import BenchmarkResult

        result = BenchmarkResult(
            filename="test.smt2",
            suite="qf_ax",
            division="samples",
            expected="sat",
            actual="unsat",
            time_ms=10.5
        )

        assert result.correct is False

    def test_benchmark_result_with_error(self):
        """Test result with error"""
        from benchmarks.core import BenchmarkResult

        result = BenchmarkResult(
            filename="test.smt2",
            suite="qf_ax",
            division="samples",
            expected="sat",
            actual="error",
            time_ms=10.5,
            error="File not found"
        )

        assert result.correct is False
        assert result.error == "File not found"

    def test_parse_smt2_expected(self):
        """Test parsing expected result from SMT2 file"""
        from benchmarks.core import parse_smt2_expected

        with tempfile.NamedTemporaryFile(mode='w', suffix='.smt2', delete=False) as f:
            f.write("(set-info :status sat)\n")
            f.write("(declare-const x Int)\n")
            f.write("(check-sat)\n")
            filepath = f.name

        try:
            expected = parse_smt2_expected(filepath)
            assert expected == "sat"
        finally:
            os.unlink(filepath)

    def test_analyze_results(self):
        """Test results analysis"""
        from benchmarks.core import BenchmarkResult, analyze_results

        results = [
            BenchmarkResult("test1.smt2", "qf_ax", "samples", "sat", "sat", 10.0),
            BenchmarkResult("test2.smt2", "qf_ax", "samples", "sat", "unsat", 15.0),
            BenchmarkResult("test3.smt2", "qf_bv", "samples", "unsat", "unsat", 20.0),
        ]

        stats = analyze_results(results)

        assert stats['total'] == 3
        assert stats['correct'] == 2
        assert stats['incorrect'] == 1
        assert stats['errors'] == 0


class TestBenchmarkDownloaders:
    """Test benchmark downloader modules"""

    def test_qf_ax_samples_download(self):
        """Test QF_AX samples creation"""
        from benchmarks.downloaders import download_qf_ax_samples

        with tempfile.TemporaryDirectory() as tmpdir:
            count = download_qf_ax_samples(tmpdir, max_files=2)

            assert count == 2
            samples_dir = os.path.join(tmpdir, 'qf_ax', 'samples')
            assert os.path.exists(samples_dir)
            assert len([f for f in os.listdir(samples_dir) if f.endswith('.smt2')]) == 2

    def test_qf_bv_samples_download(self):
        """Test QF_BV samples creation"""
        from benchmarks.downloaders import download_qf_bv_samples

        with tempfile.TemporaryDirectory() as tmpdir:
            count = download_qf_bv_samples(tmpdir, max_files=2)

            assert count == 2
            samples_dir = os.path.join(tmpdir, 'qf_bv', 'samples')
            assert os.path.exists(samples_dir)


class TestBenchmarkRunners:
    """Test benchmark runner modules"""

    def test_qf_ax_benchmark_runner(self):
        """Test QF_AX benchmark runner"""
        from benchmarks.runners import run_qf_ax_benchmark
        from benchmarks.downloaders import download_qf_ax_samples

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create samples
            download_qf_ax_samples(tmpdir, max_files=1)

            # Get first file
            samples_dir = os.path.join(tmpdir, 'qf_ax', 'samples')
            files = [f for f in os.listdir(samples_dir) if f.endswith('.smt2')]

            if files:
                result = run_qf_ax_benchmark(tmpdir, 'samples', files[0])
                assert result.suite == 'qf_ax'
                assert result.division == 'samples'
                assert result.time_ms >= 0

    def test_qf_bv_benchmark_runner(self):
        """Test QF_BV benchmark runner"""
        from benchmarks.runners import run_qf_bv_benchmark
        from benchmarks.downloaders import download_qf_bv_samples

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create samples
            download_qf_bv_samples(tmpdir, max_files=1)

            # Get first file
            samples_dir = os.path.join(tmpdir, 'qf_bv', 'samples')
            files = [f for f in os.listdir(samples_dir) if f.endswith('.smt2')]

            if files:
                result = run_qf_bv_benchmark(tmpdir, 'samples', files[0])
                assert result.suite == 'qf_bv'
                assert result.division == 'samples'
                assert result.time_ms >= 0


class TestBenchmarkOrchestrator:
    """Test benchmark orchestrator (main coordination class)"""

    def test_orchestrator_initialization(self):
        """Test orchestrator can be created"""
        from benchmarks.orchestrator import BenchmarkOrchestrator

        with tempfile.TemporaryDirectory() as tmpdir:
            orchestrator = BenchmarkOrchestrator(cache_dir=tmpdir)

            assert orchestrator.cache_dir == tmpdir
            assert orchestrator.results == []

    def test_orchestrator_download_qf_ax_samples(self):
        """Test orchestrator can download QF_AX samples"""
        from benchmarks.orchestrator import BenchmarkOrchestrator

        with tempfile.TemporaryDirectory() as tmpdir:
            orchestrator = BenchmarkOrchestrator(cache_dir=tmpdir)
            count = orchestrator.download_qf_ax_samples(max_files=2)

            assert count == 2

    def test_orchestrator_run_qf_ax_benchmark(self):
        """Test orchestrator can run single QF_AX benchmark"""
        from benchmarks.orchestrator import BenchmarkOrchestrator

        with tempfile.TemporaryDirectory() as tmpdir:
            orchestrator = BenchmarkOrchestrator(cache_dir=tmpdir)
            orchestrator.download_qf_ax_samples(max_files=1)

            samples_dir = os.path.join(tmpdir, 'qf_ax', 'samples')
            files = [f for f in os.listdir(samples_dir) if f.endswith('.smt2')]

            if files:
                result = orchestrator.run_qf_ax_benchmark('samples', files[0])
                assert result.suite == 'qf_ax'
                assert len(orchestrator.results) == 1

    def test_orchestrator_backward_compatibility(self):
        """Test UnifiedBenchmarkRunner alias works"""
        from benchmarks.orchestrator import UnifiedBenchmarkRunner, BenchmarkOrchestrator

        # Should be the same class
        assert UnifiedBenchmarkRunner is BenchmarkOrchestrator


class TestBenchmarkCurators:
    """Test benchmark curator modules"""

    def test_qf_ax_curated_set_creation(self):
        """Test QF_AX curated set creation"""
        from benchmarks.curators import create_qf_ax_curated_set
        from benchmarks.downloaders import download_qf_ax_samples

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create sample data
            download_qf_ax_samples(tmpdir, max_files=10)

            # Move to expected location for curator
            samples_dir = os.path.join(tmpdir, 'qf_ax', 'samples')
            full_dir = os.path.join(tmpdir, 'qf_ax_full')
            shutil.copytree(samples_dir, full_dir)

            # Create curated set
            count = create_qf_ax_curated_set(tmpdir, sample_size=5, seed=42)

            assert count >= 1
            curated_dir = os.path.join(tmpdir, 'qf_ax', 'qf_ax_curated')
            assert os.path.exists(curated_dir)


class TestBackwardCompatibility:
    """Test backward compatibility with old runner interface"""

    def test_runner_imports(self):
        """Test runner.py provides backward compatible imports"""
        from benchmarks.runner import BenchmarkOrchestrator, UnifiedBenchmarkRunner

        assert BenchmarkOrchestrator is not None
        assert UnifiedBenchmarkRunner is BenchmarkOrchestrator

    def test_old_runner_interface(self):
        """Test old UnifiedBenchmarkRunner interface still works"""
        from benchmarks.runner import UnifiedBenchmarkRunner

        with tempfile.TemporaryDirectory() as tmpdir:
            runner = UnifiedBenchmarkRunner(cache_dir=tmpdir)

            # Old interface methods should exist
            assert hasattr(runner, 'download_qf_ax_samples')
            assert hasattr(runner, 'run_qf_ax_benchmark')
            assert hasattr(runner, 'analyze_results')
            assert hasattr(runner, 'print_summary')
            assert hasattr(runner, 'save_results')


class TestModuleStructure:
    """Test the new modular structure is properly organized"""

    def test_core_module_exports(self):
        """Test core module exports"""
        from benchmarks import core

        assert hasattr(core, 'BenchmarkResult')
        assert hasattr(core, 'run_smt2_with_z3')
        assert hasattr(core, 'parse_smt2_expected')
        assert hasattr(core, 'analyze_results')
        assert hasattr(core, 'print_summary')
        assert hasattr(core, 'save_results')

    def test_downloaders_module_exports(self):
        """Test downloaders module exports"""
        from benchmarks import downloaders

        assert hasattr(downloaders, 'download_qf_ax_samples')
        assert hasattr(downloaders, 'download_qf_ax_full')
        assert hasattr(downloaders, 'download_qf_bv_samples')
        assert hasattr(downloaders, 'download_qf_bv_full')
        assert hasattr(downloaders, 'download_qf_s_kaluza')
        assert hasattr(downloaders, 'download_slcomp_file')

    def test_runners_module_exports(self):
        """Test runners module exports"""
        from benchmarks import runners

        assert hasattr(runners, 'run_qf_ax_benchmark')
        assert hasattr(runners, 'run_qf_ax_division')
        assert hasattr(runners, 'run_qf_bv_benchmark')
        assert hasattr(runners, 'run_qf_bv_division')
        assert hasattr(runners, 'run_qf_s_benchmark')
        assert hasattr(runners, 'run_slcomp_benchmark')

    def test_curators_module_exports(self):
        """Test curators module exports"""
        from benchmarks import curators

        assert hasattr(curators, 'create_qf_s_curated_set')
        assert hasattr(curators, 'create_slcomp_curated_set')
        assert hasattr(curators, 'create_qf_ax_curated_set')
        assert hasattr(curators, 'create_qf_bv_curated_set')

    def test_commands_module_exports(self):
        """Test commands module exports"""
        from benchmarks import commands

        assert hasattr(commands, 'cmd_run')
        assert hasattr(commands, 'cmd_download')
        assert hasattr(commands, 'cmd_analyze')
        assert hasattr(commands, 'cmd_visualize')
