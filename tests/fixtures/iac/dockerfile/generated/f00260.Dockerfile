RUN	<< EOF `
  more \
  more \
  more \
# tail
ONBUILD	\ --mount=type=cache,target=/x
  ONBUILD ${  CMD <<EOF
EOF
ADD  k=v =	<<-EOF  `\
  last
