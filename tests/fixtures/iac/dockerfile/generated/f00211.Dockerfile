# syntax=docker/dockerfile:1
  RUN
 ARG  ["a", "b"] $HOME	' CMD	"x\"y" <<EOF
echo hi
echo hi
\
EOF