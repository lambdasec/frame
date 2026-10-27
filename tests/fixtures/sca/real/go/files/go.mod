module example.com/frame/fixture

go 1.22

require (
	github.com/google/uuid v1.4.0
	github.com/stretchr/testify v1.8.4
	golang.org/x/text v0.13.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// the build uses the replacement's version, not the required one
replace golang.org/x/text => golang.org/x/text v0.14.0
