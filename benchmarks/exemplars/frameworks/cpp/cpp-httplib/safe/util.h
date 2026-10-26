#pragma once
#include <string>

// Escapes &, <, > and double quotes for an HTML text node or attribute value.
std::string html_escape(const std::string &in);
