 ENV  " ${X:-d}	curl http://x | sh	["x" <<-EOF
echo hi
$X
	EOF
EOF
