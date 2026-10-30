# syntax=docker/dockerfile:1
WORKDIR  $
 WORKDIR <<EOF
	EOF
$X
	EOF
FROM	<<EOF
run -- `
 Copy	<<EOF	${Y#p}	"x\"y"
  ONBUILD é	${Z/a/b}	${X:+e}

  BOGUS  k=v && \
# tail