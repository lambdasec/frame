"""QF_S Benchmark Data

Extracted SMT2 benchmark strings for Kaluza, Pisa, and Woorpje benchmarks.
"""

# Kaluza comprehensive samples
comprehensive_samples = {
    # Basic concatenation tests
    'concat_eq_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= y (str.++ x "world")))
(assert (= x "hello"))
(check-sat)
; expected: sat
""",
    'concat_assoc_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(assert (= (str.++ (str.++ x y) z) (str.++ x (str.++ y z))))
(check-sat)
; expected: sat
""",
    'concat_empty_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (= x (str.++ x "")))
(assert (= x (str.++ "" x)))
(check-sat)
; expected: sat
""",
    'concat_neq_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= x "ab"))
(assert (= y "ba"))
(assert (= (str.++ x y) (str.++ y x)))
(check-sat)
; expected: unsat
""",

    # Contains operations
    'contains_sat_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (str.contains x "admin"))
(check-sat)
; expected: sat
""",
    'contains_trans_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(assert (str.contains x y))
(assert (str.contains y z))
(assert (not (str.contains x z)))
(check-sat)
; expected: unsat
""",
    'contains_substr_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= x "hello world"))
(assert (= y (str.substr x 6 5)))
(assert (str.contains x y))
(check-sat)
; expected: sat
""",
    'concat_contains_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(assert (= z (str.++ x y)))
(assert (str.contains z x))
(assert (str.contains z y))
(check-sat)
; expected: sat
""",
    'contains_empty_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (str.contains x ""))
(check-sat)
; expected: sat
""",
    'contains_self_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (str.contains x x))
(check-sat)
; expected: sat
""",

    # Length operations
    'length_eq_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (= (str.len x) 5))
(check-sat)
; expected: sat
""",
    'length_concat_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(assert (= z (str.++ x y)))
(assert (= (str.len z) (+ (str.len x) (str.len y))))
(check-sat)
; expected: sat
""",
    'length_bounds_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (>= (str.len x) 5))
(assert (<= (str.len x) 10))
(check-sat)
; expected: sat
""",
    'length_nonneg_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (< (str.len x) 0))
(check-sat)
; expected: unsat
""",
    'length_empty_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (= (str.len "") 0))
(assert (= x ""))
(assert (= (str.len x) 0))
(check-sat)
; expected: sat
""",

    # Substring operations
    'substr_basic_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= x "hello"))
(assert (= y (str.substr x 0 4)))
(assert (= y "hell"))
(check-sat)
; expected: sat
""",
    'substr_empty_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (= (str.substr x 0 0) ""))
(check-sat)
; expected: sat
""",
    'substr_length_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= x "hello"))
(assert (= y (str.substr x 1 3)))
(assert (= (str.len y) 3))
(check-sat)
; expected: sat
""",
    'substr_concat_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(assert (= x "hello"))
(assert (= y (str.substr x 0 2)))
(assert (= z (str.substr x 2 3)))
(assert (= x (str.++ y z)))
(check-sat)
; expected: sat
""",
    'substr_bounds_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= x "test"))
(assert (= y (str.substr x 0 10)))
(assert (= y x))
(check-sat)
; expected: sat
""",

    # Prefix/Suffix operations
    'prefix_sat_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (str.prefixof x y))
(assert (= x "hello"))
(assert (= y "hello world"))
(check-sat)
; expected: sat
""",
    'prefix_empty_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (str.prefixof "" x))
(check-sat)
; expected: sat
""",
    'prefix_self_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (str.prefixof x x))
(check-sat)
; expected: sat
""",
    'suffix_sat_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (str.suffixof x y))
(assert (= x "world"))
(assert (= y "hello world"))
(check-sat)
; expected: sat
""",
    'suffix_empty_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (str.suffixof "" x))
(check-sat)
; expected: sat
""",

    # IndexOf operations
    'indexof_found_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (= x "hello world"))
(assert (= (str.indexof x "world" 0) 6))
(check-sat)
; expected: sat
""",
    'indexof_notfound_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (= x "hello"))
(assert (= (str.indexof x "world" 0) (- 1)))
(check-sat)
; expected: sat
""",
    'indexof_empty_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (= (str.indexof x "" 0) 0))
(check-sat)
; expected: sat
""",

    # Replace operations
    'replace_basic_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= x "hello world"))
(assert (= y (str.replace x "world" "there")))
(assert (= y "hello there"))
(check-sat)
; expected: sat
""",
    'replace_noop_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= x "hello"))
(assert (= y (str.replace x "world" "there")))
(assert (= y x))
(check-sat)
; expected: sat
""",
    'replace_empty_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= y (str.replace x "" "a")))
(check-sat)
; expected: sat
""",

    # At (character access) operations
    'at_basic_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (= x "hello"))
(assert (= (str.at x 0) "h"))
(assert (= (str.at x 1) "e"))
(check-sat)
; expected: sat
""",
    'at_bounds_01.smt2': """(set-logic QF_S)
(declare-const x String)
(assert (= x "hi"))
(assert (= (str.at x 5) ""))
(check-sat)
; expected: sat
""",

    # Complex multi-operation scenarios
    'complex_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(assert (= x "hello"))
(assert (= y "world"))
(assert (= z (str.++ x " " y)))
(assert (str.contains z x))
(assert (str.contains z y))
(assert (= (str.len z) 11))
(check-sat)
; expected: sat
""",
    'complex_02.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= x "testing"))
(assert (= y (str.substr x 0 4)))
(assert (str.prefixof y x))
(assert (= (str.len y) 4))
(check-sat)
; expected: sat
""",
    'complex_03.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(assert (= x "abc"))
(assert (= y (str.++ x x)))
(assert (= z (str.replace y "bc" "xy")))
(assert (= z "axyabc"))
(check-sat)
; expected: sat
""",
    'complex_unsat_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= (str.len x) 5))
(assert (= (str.len y) 3))
(assert (= (str.++ x y) (str.++ y x)))
(assert (not (= x y)))
(check-sat)
; expected: unsat
""",

    # Security-relevant patterns
    'taint_sql_01.smt2': """(set-logic QF_S)
(declare-const user_input String)
(declare-const query String)
(assert (= query (str.++ "SELECT * FROM users WHERE id=" user_input)))
(assert (str.contains user_input "OR"))
(check-sat)
; expected: sat
""",
    'taint_xss_01.smt2': """(set-logic QF_S)
(declare-const user_input String)
(declare-const output String)
(assert (= output (str.++ "<div>" user_input "</div>")))
(assert (str.contains user_input "<script>"))
(check-sat)
; expected: sat
""",
    'sanitize_01.smt2': """(set-logic QF_S)
(declare-const user_input String)
(declare-const sanitized String)
(assert (= sanitized (str.replace user_input "'" "")))
(assert (not (str.contains sanitized "'")))
(check-sat)
; expected: sat
"""
}

# Pisa samples
pisa_samples = {
    'path_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const cond Bool)
(assert (ite cond (= y (str.++ x "admin")) (= y (str.++ x "user"))))
(assert (str.contains y "admin"))
(check-sat)
; expected: sat
""",
    'path_02.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const result String)
(declare-const flag Bool)
(assert (ite flag (= result (str.replace x "'" "")) (= result x)))
(assert (str.contains result "'"))
(assert flag)
(check-sat)
; expected: unsat
""",
    'branch_merge_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(declare-const b1 Bool)
(declare-const b2 Bool)
(assert (ite b1 (= y (str.++ x "a")) (= y (str.++ x "b"))))
(assert (ite b2 (= z (str.++ y "c")) (= z (str.++ y "d"))))
(assert (= (str.len z) (+ (str.len x) 2)))
(check-sat)
; expected: sat
""",
    'loop_invariant_01.smt2': """(set-logic QF_S)
(declare-const x0 String)
(declare-const x1 String)
(declare-const x2 String)
(assert (= x1 (str.++ x0 "a")))
(assert (= x2 (str.++ x1 "a")))
(assert (= (str.len x2) (+ (str.len x0) 2)))
(check-sat)
; expected: sat
""",
    'symbolic_exec_01.smt2': """(set-logic QF_S)
(declare-const input String)
(declare-const output String)
(declare-const sanitized String)
(assert (= sanitized (str.replace input "<" "&lt;")))
(assert (= output (str.++ "<html>" sanitized "</html>")))
(assert (str.contains output "<script>"))
(check-sat)
; expected: sat
"""
}

# Woorpje samples
woorpje_samples = {
    'word_eq_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= (str.++ x y) (str.++ y x)))
(assert (not (= x y)))
(assert (not (= x "")))
(assert (not (= y "")))
(check-sat)
; expected: sat
""",
    'word_eq_02.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(assert (= (str.++ x y) (str.++ y z)))
(assert (not (= y "")))
(check-sat)
; expected: sat
""",
    'word_eq_03.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= (str.++ x x) (str.++ y y y)))
(check-sat)
; expected: sat
""",
    'quadratic_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(assert (= (str.++ x x) (str.++ y y)))
(assert (not (= x y)))
(check-sat)
; expected: sat
""",
    'periodic_01.smt2': """(set-logic QF_S)
(declare-const x String)
(declare-const y String)
(declare-const z String)
(assert (= (str.++ x y z) (str.++ y z x)))
(assert (= (str.len x) 3))
(assert (= (str.len y) 2))
(check-sat)
; expected: sat
"""
}

