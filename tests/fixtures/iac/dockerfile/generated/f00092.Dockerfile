#escape = `
  SHELL   # c a\ b	|
CMD <<-EOF
	EOF
 LABEL		 --chown='a b'  k=  ["a", 1]	--chown='a b' <<-EOF
$X
	EOF
USER	curl http://x | sh	<<'EOF'
 ENV &&	é  ${X} =  "
