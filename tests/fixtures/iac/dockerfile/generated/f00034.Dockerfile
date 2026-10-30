  COPY ${X} 's t'
 EXPOSE	CMD	["a", "b"] << ${X:-d}	<<EOF <<EOF
\
$X
	EOF
	EOF
  ARG	"	<<"E F"

 ARG	k=v	k="v w"	<< EOF\  
  more \

x`

HEALTHCHECK  --chown='a b'  a 2<<X
ENTRYPOINT --chown='a b'	# << EOF
  ONBUILD  ["a", 1]