  SHELL  ${Z/a/b}  <<	k="v w" " <<EOF
\
$X
$X
	EOF
ARG	$ k=v
	
 CMD  `	    = <<EOF
	EOF
  USER  ` <<-EOF
$X
echo hi
$X
	EOF
  ADD b=c a\ b " []  ;

