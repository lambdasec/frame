FROM <<EOF
ADD  ["x"	NONE	["a", "b"]	's t'	[]
  ARG  NONE a     <<EOF
	EOF
  BOGUS	${X:+e} 's t'	é `
   
  more \
# tail
# c
  ENV  << ${Z/a/b}
  MAINTAINER	--from=build ${Z/a/b}	\  	\

  more \
   
# tail
# c
RUN  $ <<-EOF	${X}	${X:-d} `
   
x`
  last
MAINTAINER	 # c	curl http://x | sh