 ENTRYPOINT  {} <<  --from=build  ${X:-d}  ["a", 1]
 BOGUS
  CMD  a  --mount=type=cache,target=/x  k="v w" <<-EOF
\
	EOF
