 ENTRYPOINT  << EOF	2<<X\
\
  more \

  BOGUS	2<<X	<<'EOF'	${	<< EOF <<-EOF
EOF 
$X
EOF
  ENV	--chown='a b'  's t'	2<<X  ["x"	["a", 1]
STOPSIGNAL  --mount=type=cache,target=/x
 COPY	$HOME ${X}	${Z/a/b}  " ${X:-d}\

# comment

# tail
STOPSIGNAL	` `
\
# tail
 ADD  <<-EOF	k= <<EOF
EOF 
	EOF
EOF

