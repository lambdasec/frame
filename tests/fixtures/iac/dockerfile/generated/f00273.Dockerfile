  RUN	k="v w"
  ENTRYPOINT  <<
  ARG	<<'EOF'
  ARG  k=	[]  --mount=type=cache,target=/x  <<-EOF	NONE
