  COPY
   # c2
VOLUME '  "x\"y"  ${X:-d} NONE
LABEL  b=c --mount=type=cache,target=/x

ONBUILD
 FROM $	 # c  = <<EOF
EOF
STOPSIGNAL ["a", 1]  ` ${Y#p}  ["a", 1]
  USER  $HOME b=c

  STOPSIGNAL \
# comment

\
  last
