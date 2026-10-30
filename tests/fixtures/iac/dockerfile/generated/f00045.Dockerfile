#escape = `
HEALTHCHECK
ARG  << EOF \
# comment
# comment

  ENV ${Z/a/b}	k=v	a\ b <<-EOF
$X
EOF 
\
	EOF
ONBUILD |	"q r" ;
ENTRYPOINT	k=v <<-EOF <<-EOF
	EOF
	EOF
  STOPSIGNAL  ["a", 1] #
EXPOSE   # c  ["x"
 run  k="v w"  x y	["x"	--chown='a b'  << EOF
