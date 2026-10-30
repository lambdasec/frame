  BOGUS
   # c2
  CMD	k="v w"	[]	<<"E F"
  RUN k= x y b=c ;
  ONBUILD k="v w"	\	NONE
# c
HEALTHCHECK <<"E F" ${Z/a/b}	[]
