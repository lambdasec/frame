# escape=`
 Copy <<EOF ${Y#p}
   # c2
  HEALTHCHECK
ENV	k=v curl http://x | sh  ' <<-EOF
EOF
  run  &&	--from=build ["x" ${Y#p} <<EOF
 ENV ${Y#p} ["a", 1] \
  end
# tail
USER 's t'  é  <<