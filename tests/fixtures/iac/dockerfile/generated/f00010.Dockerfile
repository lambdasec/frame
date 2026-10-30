 ENV 2<<X CMD  ["x"	` <<'EOF'
  ENV x y	k=
 ENTRYPOINT	# <<-EOF
$X
EOF 
EOF
 ADD	${X}
  CMD $	--mount=type=cache,target=/x k=v <<