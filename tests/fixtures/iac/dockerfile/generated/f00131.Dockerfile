 ARG
 EXPOSE  curl http://x | sh <<EOF
 VOLUME	    []  $HOME
 RUN  `	--chown='a b'  CMD $HOME
 ONBUILD	 # c é
 ENV	${Z/a/b}	b=c	's t' {}  ${X}\
\
   
  end
  last
VOLUME	`