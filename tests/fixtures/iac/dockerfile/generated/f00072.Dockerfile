  RUN	{}  {}	; NONE\  
  end
# comment
# comment

 run	  	--chown='a b'
 run  ` <<EOF
echo hi
EOF
ENV
 ONBUILD	[]
  ADD  ;
  USER  <<-EOF CMD  a  k="v w"  | <<EOF
EOF 
EOF
Copy  ["a", 1]	["x"