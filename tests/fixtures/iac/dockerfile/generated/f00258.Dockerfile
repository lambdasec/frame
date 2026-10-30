CMD  # c NONE\  
  end

  last
   # c2
RUN
 FROM  #  a\ b ' <<EOF
	EOF
\
echo hi
EOF
 BOGUS <<'EOF'  <<"E F" #	"x\"y" <<-EOF
$X
	EOF
Copy  b=c		 <<'EOF' --=x
# c
 ENTRYPOINT	#	"x\"y"  x y