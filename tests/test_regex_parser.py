"""
Unit tests for regex pattern parsing and Z3 encoding

Tests the regex parser that converts regex patterns to Z3 regex AST.
"""

import pytest
import z3
from frame.encoding.regex_parser import parse_regex, RegexParseError
from frame.encoding.encoder import Z3Encoder
from frame.core.ast import StrMatches, StrLiteral, Var
from frame import parse


class TestRegexParser:
    """Test regex pattern parser"""

    def test_simple_digit_pattern(self):
        """Test [0-9]+ pattern"""
        regex = parse_regex('[0-9]+')
        s = z3.String('s')

        solver = z3.Solver()
        solver.add(z3.InRe(s, regex))
        solver.add(s == z3.StringVal('123'))
        assert solver.check() == z3.sat

    def test_letter_pattern(self):
        """Test [a-z]+ pattern"""
        regex = parse_regex('[a-z]+')
        s = z3.String('s')

        solver = z3.Solver()
        solver.add(z3.InRe(s, regex))
        solver.add(s == z3.StringVal('hello'))
        assert solver.check() == z3.sat

    def test_uppercase_pattern(self):
        """Test [A-Z]+ pattern"""
        regex = parse_regex('[A-Z]+')
        s = z3.String('s')

        solver = z3.Solver()
        solver.add(z3.InRe(s, regex))
        solver.add(s == z3.StringVal('HELLO'))
        assert solver.check() == z3.sat

    def test_mixed_character_class(self):
        """Test [a-zA-Z0-9]+ pattern"""
        regex = parse_regex('[a-zA-Z0-9]+')
        s = z3.String('s')

        solver = z3.Solver()
        solver.add(z3.InRe(s, regex))
        solver.add(s == z3.StringVal('Test123'))
        assert solver.check() == z3.sat

    def test_star_quantifier(self):
        """Test a* pattern"""
        regex = parse_regex('a*')
        s = z3.String('s')

        # Empty string should match
        solver1 = z3.Solver()
        solver1.add(z3.InRe(s, regex))
        solver1.add(s == z3.StringVal(''))
        assert solver1.check() == z3.sat

        # 'aaa' should match
        solver2 = z3.Solver()
        solver2.add(z3.InRe(s, regex))
        solver2.add(s == z3.StringVal('aaa'))
        assert solver2.check() == z3.sat

    def test_plus_quantifier(self):
        """Test a+ pattern"""
        regex = parse_regex('a+')
        s = z3.String('s')

        # Empty string should NOT match
        solver1 = z3.Solver()
        solver1.add(z3.InRe(s, regex))
        solver1.add(s == z3.StringVal(''))
        assert solver1.check() == z3.unsat

        # 'aaa' should match
        solver2 = z3.Solver()
        solver2.add(z3.InRe(s, regex))
        solver2.add(s == z3.StringVal('aaa'))
        assert solver2.check() == z3.sat

    def test_optional_quantifier(self):
        """Test a? pattern"""
        regex = parse_regex('a?')
        s = z3.String('s')

        # Empty string should match
        solver1 = z3.Solver()
        solver1.add(z3.InRe(s, regex))
        solver1.add(s == z3.StringVal(''))
        assert solver1.check() == z3.sat

        # 'a' should match
        solver2 = z3.Solver()
        solver2.add(z3.InRe(s, regex))
        solver2.add(s == z3.StringVal('a'))
        assert solver2.check() == z3.sat

    def test_concatenation(self):
        """Test abc pattern (concatenation)"""
        regex = parse_regex('abc')
        s = z3.String('s')

        solver = z3.Solver()
        solver.add(z3.InRe(s, regex))
        solver.add(s == z3.StringVal('abc'))
        assert solver.check() == z3.sat

    def test_alternation(self):
        """Test a|b pattern"""
        regex = parse_regex('a|b')
        s = z3.String('s')

        # 'a' should match
        solver1 = z3.Solver()
        solver1.add(z3.InRe(s, regex))
        solver1.add(s == z3.StringVal('a'))
        assert solver1.check() == z3.sat

        # 'b' should match
        solver2 = z3.Solver()
        solver2.add(z3.InRe(s, regex))
        solver2.add(s == z3.StringVal('b'))
        assert solver2.check() == z3.sat

    def test_grouping(self):
        """Test (ab)+ pattern"""
        regex = parse_regex('(ab)+')
        s = z3.String('s')

        solver = z3.Solver()
        solver.add(z3.InRe(s, regex))
        solver.add(s == z3.StringVal('ababab'))
        assert solver.check() == z3.sat

    def test_escape_sequences(self):
        """Test escape sequences like \\d"""
        # \\d is same as [0-9]
        regex = parse_regex('\\d+')
        s = z3.String('s')

        solver = z3.Solver()
        solver.add(z3.InRe(s, regex))
        solver.add(s == z3.StringVal('789'))
        assert solver.check() == z3.sat

    def test_word_characters(self):
        """Test \\w for word characters"""
        regex = parse_regex('\\w+')
        s = z3.String('s')

        solver = z3.Solver()
        solver.add(z3.InRe(s, regex))
        solver.add(s == z3.StringVal('Hello_123'))
        assert solver.check() == z3.sat

    def test_dot_any_character(self):
        """Test . for any character"""
        regex = parse_regex('a.c')
        s = z3.String('s')

        solver = z3.Solver()
        solver.add(z3.InRe(s, regex))
        solver.add(s == z3.StringVal('abc'))
        assert solver.check() == z3.sat

    def test_literal_special_chars(self):
        """Test escaping special characters"""
        regex = parse_regex('\\.')
        s = z3.String('s')

        solver = z3.Solver()
        solver.add(z3.InRe(s, regex))
        solver.add(s == z3.StringVal('.'))
        assert solver.check() == z3.sat

    def test_email_pattern(self):
        """Test realistic email pattern"""
        # Simplified email: [a-zA-Z0-9]+@[a-zA-Z0-9]+\\.[a-z]+
        regex = parse_regex('[a-zA-Z0-9]+@[a-zA-Z0-9]+\\.[a-z]+')
        s = z3.String('s')

        solver = z3.Solver()
        solver.add(z3.InRe(s, regex))
        solver.add(s == z3.StringVal('user@example.com'))
        assert solver.check() == z3.sat

    def test_phone_pattern(self):
        """Test phone number pattern"""
        # Pattern: \\d\\d\\d-\\d\\d\\d\\d
        regex = parse_regex('\\d\\d\\d-\\d\\d\\d\\d')
        s = z3.String('s')

        solver = z3.Solver()
        solver.add(z3.InRe(s, regex))
        solver.add(s == z3.StringVal('555-1234'))
        assert solver.check() == z3.sat


class TestRegexWithEncoder:
    """Test regex with Z3 encoder"""

    def test_str_matches_simple(self):
        """Test encoding regex matching"""
        encoder = Z3Encoder()
        matches = StrMatches(StrLiteral("123"), "[0-9]+")
        z3_formula = encoder.encode_pure(matches)

        solver = z3.Solver()
        solver.add(z3_formula)
        assert solver.check() == z3.sat

    def test_str_matches_negative(self):
        """Test regex that should NOT match"""
        encoder = Z3Encoder()
        # "abc" should NOT match digit pattern
        matches = StrMatches(StrLiteral("abc"), "[0-9]+")
        z3_formula = encoder.encode_pure(matches)

        solver = z3.Solver()
        solver.add(z3_formula)
        assert solver.check() == z3.unsat

    def test_str_matches_with_variable(self):
        """Test regex matching with variable"""
        encoder = Z3Encoder()
        matches = StrMatches(Var("input"), "[a-z]+")
        z3_formula = encoder.encode_pure(matches)

        solver = z3.Solver()
        input_str = encoder.encode_string_expr(Var("input"))
        solver.add(z3_formula)
        solver.add(input_str == z3.StringVal("hello"))
        assert solver.check() == z3.sat

    def test_email_validation(self):
        """Test email validation pattern"""
        encoder = Z3Encoder()
        email_pattern = "[a-zA-Z0-9]+@[a-zA-Z0-9]+\\.[a-z]+"
        matches = StrMatches(Var("email"), email_pattern)
        z3_formula = encoder.encode_pure(matches)

        solver = z3.Solver()
        email_str = encoder.encode_string_expr(Var("email"))
        solver.add(z3_formula)
        solver.add(email_str == z3.StringVal("test@example.com"))
        assert solver.check() == z3.sat

    def test_password_strength(self):
        """Test password strength pattern"""
        encoder = Z3Encoder()
        # At least one letter and one digit
        pwd_pattern = "[a-zA-Z0-9]+"
        matches = StrMatches(Var("password"), pwd_pattern)
        z3_formula = encoder.encode_pure(matches)

        solver = z3.Solver()
        pwd_str = encoder.encode_string_expr(Var("password"))
        solver.add(z3_formula)
        solver.add(pwd_str == z3.StringVal("Pass123"))
        assert solver.check() == z3.sat


class TestRegexInSecurityContext:
    """Test regex in security analysis context"""

    def test_sql_injection_pattern_detection(self):
        """Test detecting SQL injection patterns"""
        # Test that we can match strings containing quotes
        encoder = Z3Encoder()
        # Pattern to detect single quote character
        matches = StrMatches(Var("user_input"), ".*'.*")
        z3_formula = encoder.encode_pure(matches)

        solver = z3.Solver()
        input_str = encoder.encode_string_expr(Var("user_input"))
        solver.add(z3_formula)
        solver.add(input_str == z3.StringVal("admin' OR '1'='1"))
        assert solver.check() == z3.sat

    def test_xss_pattern_detection(self):
        """Test detecting XSS patterns"""
        encoder = Z3Encoder()
        # Pattern to detect <script> tag
        matches = StrMatches(Var("user_input"), ".*<script>.*")
        z3_formula = encoder.encode_pure(matches)

        solver = z3.Solver()
        input_str = encoder.encode_string_expr(Var("user_input"))
        solver.add(z3_formula)
        solver.add(input_str == z3.StringVal("<script>alert(1)</script>"))
        assert solver.check() == z3.sat

    def test_path_traversal_pattern(self):
        """Test detecting path traversal patterns"""
        encoder = Z3Encoder()
        # Path contains ".."
        matches = StrMatches(Var("path"), ".*\\.\\..*")
        z3_formula = encoder.encode_pure(matches)

        solver = z3.Solver()
        path_str = encoder.encode_string_expr(Var("path"))
        solver.add(z3_formula)
        solver.add(path_str == z3.StringVal("../../etc/passwd"))
        assert solver.check() == z3.sat


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
