#escape = `
# escape=`
USER    		  <<EOF

 ENV
 RUN  2<<X "q r"   # c\  
# tail
 ENTRYPOINT 	  b=c  << EOF
  CMD |	k=v
  USER	["a", "b"]