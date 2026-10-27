module example.com/frame/fixture

go 1.22

require (
	github.com/google/uuid v1.4.0
	golang.org/x/text v0.13.0
	github.com/stretchr/testify v1.8.4
)

// the build uses the replacement's version, not the required one
replace golang.org/x/text => golang.org/x/text v0.14.0
