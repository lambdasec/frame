# check=skip=all
# escape=`
 MAINTAINER   \  
   
# comment
  end
# tail
 RUN	<< `
  last
  LABEL  {}  curl http://x | sh <<EOF
	EOF
  BOGUS	k="v w"	|
# c
STOPSIGNAL	${X:+e} "q r"	'