 ADD
RUN	CMD  ${
  LABEL  <<EOF <<-EOF
  CMD
  STOPSIGNAL k=v \  <<-EOF ["a", "b"]
 Copy "x\"y"  <<EOF 's t'
  ADD	["a", "b"]	--mount=type=cache,target=/x k=v
  HEALTHCHECK  's t'  $HOME
