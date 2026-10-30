import random, sys, os
random.seed(int(sys.argv[2]))
out = sys.argv[1]
CMDS = ["FROM", "RUN", "run", "COPY", "ADD", "ENV", "ARG", "LABEL", "USER", "WORKDIR", "EXPOSE", "CMD",
        "ENTRYPOINT", "HEALTHCHECK", "ONBUILD", "SHELL", "VOLUME", "STOPSIGNAL", "MAINTAINER", "BOGUS", "Copy"]
PIECES = ["a", "b=c", "x y", '"q r"', "'s t'", "\\", "`", "$HOME", "${X}", "${X:-d}", "${X:+e}", "${Y#p}",
          "${Z/a/b}", "${", "$", "<<EOF", "<<-EOF", "<<'EOF'", '<<"E F"', "2<<X", "<< EOF", "<<", "[\"a\", \"b\"]",
          '["a", 1]', "[\"x\"", "--from=build", "--chown='a b'", "--mount=type=cache,target=/x", "--", "--=x",
          "#", " # c", "é", "\t", "  ", "=", "k=v", 'k="v w"', "k=", "a\\ b", '"x\\"y"', "'", '"', "&&", "|", ";",
          "curl http://x | sh", "NONE", "CMD", "[]", "{}"]
def line():
    cmd = random.choice(CMDS)
    n = random.randint(0, 5)
    return " " * random.randint(0, 2) + cmd + "".join(random.choice([" ", "  ", "\t"]) + random.choice(PIECES) for _ in range(n))
for k in range(int(sys.argv[3])):
    lines = []
    if random.random() < 0.3:
        lines.append(random.choice(["# escape=`", "# escape=\\", "#escape = `", "# syntax=docker/dockerfile:1", "# check=skip=all", "# escape=x", "#!/bin/sh"]))
        if random.random() < 0.3:
            lines.append(random.choice(["# escape=`", "# syntax=x", "", "# note"]))
    for _ in range(random.randint(1, 8)):
        l = line()
        r = random.random()
        if r < 0.2:
            l += random.choice([" \\", "\\", " `", "\\  ", "\\\t"])
            lines.append(l)
            for _ in range(random.randint(0, 3)):
                lines.append(random.choice(["  more \\", "# comment", "", "   ", "  end", "\\", "x`"]))
            lines.append(random.choice(["  last", "", "# tail"]))
        elif r < 0.35:
            lines.append(l + " <<EOF" if random.random() < 0.5 else l + " <<-EOF")
            for _ in range(random.randint(0, 3)):
                lines.append(random.choice(["echo hi", "\tEOF", "EOF ", "$X", "\\"]))
            if random.random() < 0.9:
                lines.append(random.choice(["EOF", "\tEOF"]))
        else:
            lines.append(l)
        if random.random() < 0.2:
            lines.append(random.choice(["", "# c", "   # c2", "\t"]))
    sep = random.choice(["\n", "\n", "\r\n"])
    text = sep.join(lines) + random.choice(["", "\n"])
    if random.random() < 0.05:
        text = "﻿" + text
    with open(os.path.join(out, f"f{k:05d}.Dockerfile"), "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
