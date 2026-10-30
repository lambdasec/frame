ENV	[]  $ $HOME
  CMD
 ENV	   NONE	$HOME	${X} ${X:-d}
	
  ENV a\ b	CMD

 EXPOSE 2<<X NONE ${X:-d}  '	curl http://x | sh