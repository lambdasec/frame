 WORKDIR curl http://x | sh
	
  ADD  --chown='a b' ${Z/a/b} << EOF

VOLUME  ${X:-d}	CMD
  USER <<EOF
echo hi
	EOF
$X
EOF
 HEALTHCHECK  k=	a	' && 2<<X
