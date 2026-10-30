# syntax=docker/dockerfile:1
 BOGUS	x y	<<'EOF'	#  <<'EOF'  $ <<-EOF
$X
	EOF
EOF 
EOF
run	"x\"y"	${Y#p} <<EOF
$X
echo hi
EOF

  RUN	#  | curl http://x | sh
  LABEL  a NONE	#  << EOF	${X} \
  end
# comment
# tail

EXPOSE <<EOF
$X
echo hi
	EOF