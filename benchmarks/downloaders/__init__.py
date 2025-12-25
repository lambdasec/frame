"""Benchmark downloaders"""

from benchmarks.downloaders.qf_ax import download_qf_ax_samples, download_qf_ax_full
from benchmarks.downloaders.qf_bv import download_qf_bv_samples, download_qf_bv_full
from benchmarks.downloaders.qf_s import (
    download_qf_s_kaluza, download_qf_s_kaluza_full,
    download_qf_s_pisa, download_qf_s_woorpje,
    download_full_kaluza, download_full_pisa,
    download_full_appscan, download_full_pyex
)
from benchmarks.downloaders.slcomp import download_slcomp_file, download_slcomp_division
from benchmarks.downloaders.utils import download_gdrive_file, extract_archive

# SAST benchmarks
from benchmarks.downloaders.owasp_python import (
    download_owasp_python,
    create_owasp_python_curated_set,
    load_owasp_python_expected_results,
    get_owasp_python_test_files,
)
from benchmarks.downloaders.owasp_java import (
    download_owasp_java,
    create_owasp_java_curated_set,
    load_owasp_java_expected_results,
    get_owasp_java_test_files,
)
from benchmarks.downloaders.juliet import (
    download_juliet,
    create_juliet_curated_set,
    get_juliet_test_files,
    parse_juliet_testcase,
)
from benchmarks.downloaders.issueblot import (
    download_issueblot,
    create_issueblot_curated_set,
    get_issueblot_test_files,
)
from benchmarks.downloaders.secbench_js import (
    download_secbench_js,
    create_secbench_curated_set,
    get_secbench_test_files,
    load_secbench_manifest,
)

__all__ = [
    # QF_AX
    'download_qf_ax_samples', 'download_qf_ax_full',
    # QF_BV
    'download_qf_bv_samples', 'download_qf_bv_full',
    # QF_S
    'download_qf_s_kaluza', 'download_qf_s_kaluza_full',
    'download_qf_s_pisa', 'download_qf_s_woorpje',
    'download_full_kaluza', 'download_full_pisa',
    'download_full_appscan', 'download_full_pyex',
    # SL-COMP
    'download_slcomp_file', 'download_slcomp_division',
    # Utils
    'download_gdrive_file', 'extract_archive',
    # SAST - OWASP Python
    'download_owasp_python', 'create_owasp_python_curated_set',
    'load_owasp_python_expected_results', 'get_owasp_python_test_files',
    # SAST - OWASP Java
    'download_owasp_java', 'create_owasp_java_curated_set',
    'load_owasp_java_expected_results', 'get_owasp_java_test_files',
    # SAST - Juliet C/C++
    'download_juliet', 'create_juliet_curated_set',
    'get_juliet_test_files', 'parse_juliet_testcase',
    # SAST - IssueBlot.NET C#
    'download_issueblot', 'create_issueblot_curated_set', 'get_issueblot_test_files',
    # SAST - SecBench.js JavaScript
    'download_secbench_js', 'create_secbench_curated_set',
    'get_secbench_test_files', 'load_secbench_manifest',
]
