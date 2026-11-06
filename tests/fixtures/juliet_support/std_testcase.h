/* Minimal Juliet testcasesupport shim: just enough for the CWE190 int cases to
   compile standalone (the real testcasesupport is not vendored). Header-only so
   no extra object needs linking. */
#ifndef STD_TESTCASE_H
#define STD_TESTCASE_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#ifndef CHAR_ARRAY_SIZE
#define CHAR_ARRAY_SIZE 64
#endif
static void printLine(const char *s){ if (s) printf("%s\n", s); }
static void printIntLine(int x){ printf("%d\n", x); }
static void printUnsignedLine(unsigned x){ printf("%u\n", x); }
static void printLongLine(long x){ printf("%ld\n", x); }
static void printLongLongLine(long long x){ printf("%lld\n", x); }
static void printHexCharLine(char c){ printf("%02x\n", (unsigned char)c); }
static void printFloatLine(float f){ printf("%f\n", f); }
static void printDoubleLine(double d){ printf("%f\n", d); }
static int globalReturnsTrue(void){ return 1; }
static int globalReturnsFalse(void){ return 0; }
static int globalReturnsTrueOrFalse(void){ return 1; }
#endif
