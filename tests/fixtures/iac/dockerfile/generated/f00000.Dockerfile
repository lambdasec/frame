BOGUS ${X}
  ENTRYPOINT	   a\ b  ${Z/a/b}  curl http://x | sh
  CMD ${X:-d}  " k=v <<-EOF
	EOF

 HEALTHCHECK	\
