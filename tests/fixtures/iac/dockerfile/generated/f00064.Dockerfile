Copy	;  ;	$
 ADD --chown='a b'
 COPY  # c	"x\"y"
	
ONBUILD	CMD <<EOF
	EOF
\
$X
	EOF
  USER  << EOF  --chown='a b'	${X}  	  curl http://x | sh `
  last
 HEALTHCHECK --chown='a b' x y &&\  
   
# comment
  last
  LABEL