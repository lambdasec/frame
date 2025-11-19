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
]
