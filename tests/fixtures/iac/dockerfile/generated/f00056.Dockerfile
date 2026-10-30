# check=skip=all
 WORKDIR ["a", "b"] ${\

  end
# tail
MAINTAINER  []  		<< EOF <<-EOF
	EOF
EOF 
\
	EOF
USER  x y  ["a", "b"]	-- <<EOF
$X
EOF
	
 FROM  "q r"	["x"	${X}  's t'
  ADD  ${X:+e}
  FROM $HOME {}  --
