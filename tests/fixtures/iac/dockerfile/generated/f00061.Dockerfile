 EXPOSE
WORKDIR	k="v w"
ENV  --chown='a b'  ["a", "b"]   # c
   # c2
ONBUILD a\ b	`  --from=build <<EOF <<EOF
EOF

  ARG  "	["a", "b"] ["a", 1] <<EOF
EOF 
  RUN <<EOF
	EOF
ENTRYPOINT	#  ${Z/a/b}  curl http://x | sh --from=build