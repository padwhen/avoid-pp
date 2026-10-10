// A separate module from the gateway, deliberately.
//
// The wire types already exist in gateway/internal/contract, and `internal`
// means no caller outside the gateway can reach them — which is the whole
// reason this package exists. Vendoring the server module into a client
// would also make every consumer depend on the service's own dependencies.
//
// Standard library only, so there is no go.sum and nothing to audit.
module github.com/padwhen/avoid-pp/sdk/go

go 1.27.2
