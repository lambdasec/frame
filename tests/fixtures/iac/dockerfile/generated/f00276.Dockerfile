#escape = `
SHELL
 EXPOSE a --from=build		 k=	${Y#p} <<-EOF
\
  USER  CMD 's t'
  Copy  é ${X:+e}  2<<X a\ b b=c
  CMD # ["a", 1]  CMD\  

\
  more \
  last
  WORKDIR  # ${Y#p} "  <<EOF
ENTRYPOINT
