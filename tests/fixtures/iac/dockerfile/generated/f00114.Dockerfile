  run	--mount=type=cache,target=/x	k="v w"  ["a", "b"]  ["a", "b"]\
  end

EXPOSE

SHELL	--mount=type=cache,target=/x ${X} $HOME  ["a", "b"]
  ADD  << EOF	${X:-d} k="v w"  CMD
ENV <<EOF
