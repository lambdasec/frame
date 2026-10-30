VOLUME  \ 	 ${X:+e}  {}
 MAINTAINER
  VOLUME  ;  ${X:-d}	b=c	<<"E F"
 RUN  ${X:-d} "q r"	["a", "b"]
HEALTHCHECK  <<'EOF'	${ =  "x\"y"
	
  CMD	${X:+e}	-- \
   
  more \
  more \

run  =  ["a", "b"]