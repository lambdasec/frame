  Copy  k=	--mount=type=cache,target=/x  <<'EOF'	${X:+e}
   # c2
 ADD  ${Y#p}  &&	 # c
 ONBUILD # &&  ${Z/a/b} ["a", "b"]