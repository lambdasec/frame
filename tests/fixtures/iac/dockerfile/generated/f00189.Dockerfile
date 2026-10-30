#escape = `
# note
 ARG	k=v  ${X:-d}
COPY ${Z/a/b}   # c <<-EOF
 WORKDIR
CMD

  ONBUILD  =
 COPY     NONE --=x	--=x <<EOF
	EOF
	
  ARG curl http://x | sh	's t' `
x`
  end
# tail
  FROM  curl http://x | sh	2<<X	<<EOF  &&	k=v <<-EOF
EOF