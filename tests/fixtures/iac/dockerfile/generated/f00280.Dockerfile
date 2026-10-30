FROM
 LABEL	["x"  --=x  k=v #
 ARG NONE	a\ b	#
   # c2
STOPSIGNAL k="v w"	\	${Z/a/b} <<-EOF CMD
  VOLUME	é	k=  |  # c << EOF
ENV	curl http://x | sh	"q r"  ;
HEALTHCHECK  ${X} `



ONBUILD  []	<<EOF
