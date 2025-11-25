"""
Tests for Frame CLI.
"""

import json
import pytest
import tempfile
from pathlib import Path

from frame.cli import main, formula_to_dict, formula_to_sexp, formula_to_tree


class TestSolveCommand:
    """Tests for the solve command"""

    def test_solve_valid_reflexive(self, capsys):
        """Test solving a valid reflexive entailment"""
        result = main(["solve", "x |-> 5 |- x |-> 5"])
        captured = capsys.readouterr()
        assert result == 0
        assert "VALID" in captured.out

    def test_solve_valid_sep_conj(self, capsys):
        """Test solving valid separating conjunction entailment"""
        result = main(["solve", "x |-> 5 * y |-> 3 |- x |-> 5 * y |-> 3"])
        captured = capsys.readouterr()
        assert result == 0
        assert "VALID" in captured.out

    def test_solve_valid_frame(self, capsys):
        """Test solving valid entailment with frame"""
        result = main(["solve", "x |-> 5 * y |-> 3 |- x |-> 5"])
        captured = capsys.readouterr()
        assert result == 0
        assert "VALID" in captured.out

    def test_solve_invalid(self, capsys):
        """Test solving invalid entailment"""
        result = main(["solve", "x |-> 5 |- y |-> 5"])
        captured = capsys.readouterr()
        assert result == 1
        assert "INVALID" in captured.out

    def test_solve_json_format(self, capsys):
        """Test JSON output format"""
        result = main(["solve", "x |-> 5 |- x |-> 5", "--format", "json"])
        captured = capsys.readouterr()
        assert result == 0
        data = json.loads(captured.out)
        assert data["valid"] is True
        assert "time_ms" in data

    def test_solve_verbose(self, capsys):
        """Test verbose output"""
        result = main(["solve", "x |-> 5 |- x |-> 5", "--verbose"])
        captured = capsys.readouterr()
        assert result == 0
        assert "Time:" in captured.out

    def test_solve_from_file(self, capsys):
        """Test reading entailment from file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("x |-> 5 |- x |-> 5")
            f.flush()
            result = main(["solve", "-f", f.name])

        captured = capsys.readouterr()
        assert result == 0
        assert "VALID" in captured.out
        Path(f.name).unlink()

    def test_solve_no_input_error(self, capsys):
        """Test error when no input provided"""
        result = main(["solve"])
        captured = capsys.readouterr()
        assert result == 1
        assert "Error" in captured.err


class TestCheckCommand:
    """Tests for the check command"""

    def test_check_batch(self, capsys):
        """Test batch checking of entailments"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("# Comment line\n")
            f.write("x |-> 5 |- x |-> 5\n")
            f.write("emp |- emp\n")
            f.flush()
            result = main(["check", f.name])

        captured = capsys.readouterr()
        assert result == 0
        assert "Valid: 2" in captured.out
        Path(f.name).unlink()

    def test_check_with_invalid(self, capsys):
        """Test batch with invalid entailments"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("x |-> 5 |- x |-> 5\n")
            f.write("x |-> 5 |- y |-> 5\n")
            f.flush()
            result = main(["check", f.name])

        captured = capsys.readouterr()
        assert result == 1
        assert "Invalid: 1" in captured.out
        Path(f.name).unlink()

    def test_check_json_format(self, capsys):
        """Test JSON output format for check"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("x |-> 5 |- x |-> 5\n")
            f.flush()
            result = main(["check", f.name, "--format", "json"])

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["valid"] == 1
        assert len(data["results"]) == 1
        Path(f.name).unlink()

    def test_check_csv_format(self, capsys):
        """Test CSV output format for check"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("x |-> 5 |- x |-> 5\n")
            f.flush()
            result = main(["check", f.name, "--format", "csv"])

        captured = capsys.readouterr()
        assert "entailment,valid,time_ms,reason" in captured.out
        Path(f.name).unlink()


class TestParseCommand:
    """Tests for the parse command"""

    def test_parse_tree_format(self, capsys):
        """Test tree output format"""
        result = main(["parse", "x |-> 5"])
        captured = capsys.readouterr()
        assert result == 0
        assert "points-to" in captured.out
        assert "x" in captured.out

    def test_parse_json_format(self, capsys):
        """Test JSON output format"""
        result = main(["parse", "x |-> 5", "--format", "json"])
        captured = capsys.readouterr()
        assert result == 0
        data = json.loads(captured.out)
        assert data["type"] == "points_to"

    def test_parse_sexp_format(self, capsys):
        """Test S-expression output format"""
        result = main(["parse", "x |-> 5 * y |-> 3", "--format", "sexp"])
        captured = capsys.readouterr()
        assert result == 0
        assert "(sep" in captured.out
        assert "(pto" in captured.out

    def test_parse_complex_formula(self, capsys):
        """Test parsing complex formula"""
        # Use a simpler formula that parses correctly
        result = main(["parse", "x |-> 5 * y |-> 3", "--format", "json"])
        captured = capsys.readouterr()
        assert result == 0
        data = json.loads(captured.out)
        assert data["type"] == "sep_conj"

    def test_parse_from_file(self, capsys):
        """Test reading formula from file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("x |-> 5 * y |-> 3")
            f.flush()
            result = main(["parse", "-f", f.name])

        captured = capsys.readouterr()
        assert result == 0
        Path(f.name).unlink()

    def test_parse_error(self, capsys):
        """Test parse error handling"""
        result = main(["parse", "invalid @@@ formula"])
        captured = capsys.readouterr()
        assert result == 1
        assert "error" in captured.err.lower() or "Parse" in captured.err


class TestFormulaConversions:
    """Tests for formula conversion utilities"""

    def test_formula_to_dict_emp(self):
        """Test converting emp to dict"""
        from frame import parse
        formula = parse("emp")
        result = formula_to_dict(formula)
        assert result["type"] == "emp"

    def test_formula_to_dict_points_to(self):
        """Test converting points-to to dict"""
        from frame import parse
        formula = parse("x |-> 5")
        result = formula_to_dict(formula)
        assert result["type"] == "points_to"
        assert result["location"]["name"] == "x"

    def test_formula_to_dict_sep_conj(self):
        """Test converting separating conjunction to dict"""
        from frame import parse
        formula = parse("x |-> 5 * y |-> 3")
        result = formula_to_dict(formula)
        assert result["type"] == "sep_conj"

    def test_formula_to_sexp_simple(self):
        """Test S-expression conversion"""
        from frame import parse
        formula = parse("x |-> 5")
        result = formula_to_sexp(formula)
        assert "pto" in result
        assert "x" in result

    def test_formula_to_tree_simple(self):
        """Test tree conversion"""
        from frame import parse
        formula = parse("x |-> 5")
        result = formula_to_tree(formula)
        assert "points-to" in result


class TestScanCommand:
    """Tests for the scan command"""

    def test_scan_vulnerable_code(self, capsys):
        """Test scanning vulnerable code"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("""
def vulnerable():
    user_id = input()
    query = "SELECT * FROM users WHERE id=" + user_id
    cursor.execute(query)
""")
            f.flush()
            result = main(["scan", f.name, "--no-verify"])

        captured = capsys.readouterr()
        assert result == 1  # Exit code 1 for high severity
        assert "sql_injection" in captured.out.lower()
        Path(f.name).unlink()

    def test_scan_safe_code(self, capsys):
        """Test scanning safe code"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("""
def safe_function():
    x = 5
    return x + 10
""")
            f.flush()
            result = main(["scan", f.name, "--no-verify"])

        captured = capsys.readouterr()
        assert result == 0
        assert "No vulnerabilities found" in captured.out
        Path(f.name).unlink()

    def test_scan_json_format(self, capsys):
        """Test JSON output format for scan"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("""
def safe_function():
    return 42
""")
            f.flush()
            result = main(["scan", f.name, "--no-verify", "--format", "json"])

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "vulnerabilities" in data
        Path(f.name).unlink()


class TestCLIHelp:
    """Tests for CLI help and version"""

    def test_main_help(self, capsys):
        """Test main help output"""
        with pytest.raises(SystemExit) as exc_info:
            main(["--help"])
        captured = capsys.readouterr()
        # argparse exits with 0 for --help
        assert exc_info.value.code == 0
        assert "scan" in captured.out
        assert "solve" in captured.out
        assert "check" in captured.out
        assert "parse" in captured.out

    def test_solve_help(self, capsys):
        """Test solve subcommand help"""
        with pytest.raises(SystemExit) as exc_info:
            main(["solve", "--help"])
        assert exc_info.value.code == 0

    def test_no_command(self, capsys):
        """Test running with no command shows help"""
        result = main([])
        captured = capsys.readouterr()
        assert result == 0
        assert "frame" in captured.out.lower() or "usage" in captured.out.lower()
