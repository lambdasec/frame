ENV <<EOF
	EOF
EOF
# c
 ONBUILD  ${Y#p} -- k=v
 ARG	CMD	<<'EOF'
Copy	;	x y <<-EOF
	EOF
echo hi
echo hi
EOF
  ADD	&&  $  "	${Y#p} --mount=type=cache,target=/x
	
  ONBUILD  $ <<-EOF
EOF
