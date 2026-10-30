# escape=x
 WORKDIR
	
CMD  2<<X	["a", 1]\	
  more \
  end
   

# c
RUN <<EOF   	#  2<<X ["a", "b"]
