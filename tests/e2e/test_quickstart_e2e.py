"""The README's quickstart, executed: the findings it shows are real, and the obvious fixes clear them."""

import shutil
from pathlib import Path

from e2e_helpers import scan

QUICKSTART = Path(__file__).resolve().parents[2] / "benchmarks" / "exemplars" / "quickstart"


def test_quickstart_reports_the_two_cross_file_flaws():
    got = scan(QUICKSTART, root=QUICKSTART)
    by_line = {(f["path"], f["line"]): f for f in got.findings}
    sqli = by_line[("shop/services/orders.py", 8)]
    cmdi = by_line[("shop/services/orders.py", 13)]
    assert sqli["cwe_id"] == "CWE-89" and cmdi["cwe_id"] == "CWE-78"
    assert "shop/app.py:11" in sqli["data_flow"][0] and "shop/app.py:17" in cmdi["data_flow"][0]
    assert len(got.findings) == 2


def test_the_documented_fixes_clear_both(tmp_path):
    copy = tmp_path / "quickstart"
    shutil.copytree(QUICKSTART, copy)
    orders = copy / "shop" / "services" / "orders.py"
    text = orders.read_text()
    text = text.replace('''cur.execute("SELECT * FROM orders WHERE customer = '" + name.strip() + "'")''',
                        '''cur.execute("SELECT * FROM orders WHERE customer = ?", (name.strip(),))''')
    text = text.replace('''os.system("export-orders --format " + fmt)''',
                        '''subprocess.run(["export-orders", "--format", fmt])''').replace("import os\n", "import subprocess\n")
    orders.write_text(text)
    assert scan(copy, root=copy).findings == []
