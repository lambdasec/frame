 ADD \	"q r" --  ${X:-d}  ;
RUN
 MAINTAINER  ["a", 1]  NONE 2<<X	--chown='a b'
  LABEL  $	 # c ${X:+e}	--=x
  USER  curl http://x | sh
  STOPSIGNAL ${  x y $HOME <<EOF
\
$X
$X
	EOF
 ENTRYPOINT