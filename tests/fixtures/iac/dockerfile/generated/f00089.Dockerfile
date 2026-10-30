Copy  --=x  << EOF	"x\"y" <<EOF
	EOF
	EOF
	EOF
EOF
   # c2
  ENTRYPOINT	= ;	<<'EOF'  curl http://x | sh <<EOF
echo hi
EOF
  ONBUILD  <<EOF --chown='a b'	b=c	<<-EOF
HEALTHCHECK	b=c a	--from=build
ENTRYPOINT   # c

EXPOSE
