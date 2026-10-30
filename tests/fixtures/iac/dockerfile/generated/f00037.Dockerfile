 SHELL  --from=build  <<-EOF	["a", "b"] ${Z/a/b}
  STOPSIGNAL  a\ b	| --
 STOPSIGNAL k= --chown='a b'	--from=build
  ONBUILD	 # c k=v <<'EOF' k="v w"
   # c2