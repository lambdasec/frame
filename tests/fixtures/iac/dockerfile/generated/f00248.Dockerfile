# check=skip=all
# note
ONBUILD
 MAINTAINER --=x	["x" #
	
COPY	a\ b <<-EOF
	EOF
EOF 
EOF
ARG	--from=build	|      ;  a\ b

