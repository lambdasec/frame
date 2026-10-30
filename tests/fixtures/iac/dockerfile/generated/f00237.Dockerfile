# syntax=docker/dockerfile:1
# note
 ENTRYPOINT a b=c	b=c
  CMD	${X} <<EOF
$X
EOF 
	EOF
  MAINTAINER	<<'EOF'	--from=build