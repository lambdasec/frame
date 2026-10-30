 SHELL	=
  SHELL  k= --
ADD  ["x"  |	<< EOF	--
 HEALTHCHECK  a  ${X:+e}	curl http://x | sh  --chown='a b'  <<'EOF'\	

