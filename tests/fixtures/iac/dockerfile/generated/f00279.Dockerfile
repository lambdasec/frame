  VOLUME # << ${	--mount=type=cache,target=/x <<EOF
EOF 
$X
echo hi
	EOF

run ${
   # c2
 WORKDIR	${X:+e} \
  more \
  end

BOGUS --from=build  <<"E F"  a  ["a", "b"] a <<-EOF
echo hi
EOF

 STOPSIGNAL	"x\"y"  --  --mount=type=cache,target=/x	<<'EOF'	|
  LABEL ${Y#p}	$HOME
CMD	|  << EOF	["a", 1]