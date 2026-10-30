# escape=x
run " []
BOGUS	&&  "q r"  ["a", "b"]	a\ b \

  STOPSIGNAL	--=x CMD  x y	&& ${X:+e}\
  end
x`

MAINTAINER  ${ \
 BOGUS  <<EOF  k=v   # c k="v w"
ENV  "q r" --from=build ${X:-d} --chown='a b'
  RUN
# c
