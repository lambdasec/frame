ENTRYPOINT  k=  ${  <<"E F" <<-EOF
$X
EOF 
	EOF
EOF
EXPOSE	x y a  <<-EOF  ${  k="v w"\
# tail
  ONBUILD $ `
\
  more \
  more \
# tail
 ENV  a	${X} NONE  ["a", 1] \
\

 ENV  ${X:-d}  << NONE <<-EOF
EOF 
	EOF
   # c2
 VOLUME	--chown='a b' <<-EOF
echo hi
MAINTAINER	${X:-d}
