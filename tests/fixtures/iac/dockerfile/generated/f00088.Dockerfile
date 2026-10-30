#!/bin/sh

RUN  " <<EOF
echo hi
ARG
 USER ${Y#p}  $HOME\  

  more \
# tail
 LABEL ${X} ' <<-EOF  --
  CMD  k=v ${X}  b=c   # c
BOGUS <<-EOF
	EOF
echo hi
	EOF
   # c2
