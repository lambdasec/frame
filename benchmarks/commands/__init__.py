"""Benchmark commands"""

from benchmarks.commands.run_cmd import cmd_run
from benchmarks.commands.download_cmd import cmd_download
from benchmarks.commands.analyze_cmd import cmd_analyze
from benchmarks.commands.visualize_cmd import cmd_visualize

__all__ = [
    'cmd_run',
    'cmd_download',
    'cmd_analyze',
    'cmd_visualize',
]
