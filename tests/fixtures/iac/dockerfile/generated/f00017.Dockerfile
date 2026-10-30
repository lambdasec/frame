# check=skip=all
VOLUME
 CMD <<"E F" '

 ARG  << ;	# <<EOF
$X
echo hi
$X
EOF
  FROM  |	a ["a", 1]
