  ENTRYPOINT " <<-EOF
	EOF

 ARG
LABEL = <<-EOF
echo hi
	EOF
   # c2
SHELL ;	{}	b=c	"q r" x y <<EOF
echo hi
	EOF
LABEL <<EOF  --mount=type=cache,target=/x