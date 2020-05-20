package bearer

import (
	"context"
	"errors"
	"net/http"

	"github.com/shaj13/go-passport/auth"
	"github.com/shaj13/go-passport/storage"
)

// CachedStrategyKey export identifier for the cached bearer strategy,
// commonly used when enable/add strategy to go-passport authenticator.
const CachedStrategyKey = auth.StrategyKey("Bearer.Cached.Strategy")

// NOOP is the error returned by NoOpAuthenticate to indicate there no op,
// and signal authenticator to unauthenticate the request, See NoOpAuthenticate.
var NOOP = errors.New("NOOP")

// Authenticate decalre custom function to authenticate request using token.
// The authenticate function invoked by Authenticate Strategy method when
// The token does not exist in the cahce and the invocation result will be cached, unless an error returned.
// Use NoOpAuthenticate instead to refresh/mangae token directly using cache or Append function.
type Authenticate func(ctx context.Context, r *http.Request, token string) (auth.Info, error)

// NewCachedToken return new auth.Strategy.
// The returned strategy caches the invocation result of authenticate function, See Authenticate.
// Use NoOpAuthenticate to refresh/mangae token directly using cache or Append function, See NoOpAuthenticate.
func NewCachedToken(auth Authenticate, c storage.Cache) auth.Strategy {
	if auth == nil {
		panic("Authenticate Function required and can't be nil")
	}

	if c == nil {
		panic("Cache object required and can't be nil")
	}

	return &cachedToken{
		authFunc: auth,
		cache:    c,
	}
}

type cachedToken struct {
	cache    storage.Cache
	authFunc Authenticate
}

func (c *cachedToken) authenticate(ctx context.Context, r *http.Request, token string) (auth.Info, error) {
	info, ok, err := c.cache.Load(token, r)

	if err != nil {
		return nil, err
	}

	// if token not found invoke user authenticate function
	if !ok {
		info, err = c.authFunc(ctx, r, token)
		if err == nil {
			// cache result
			err = c.cache.Store(token, info, r)
		}
	}

	if err != nil {
		return nil, err
	}

	if _, ok := info.(auth.Info); !ok {
		return nil, storage.NewInvalidType((*auth.Info)(nil), info)
	}

	return info.(auth.Info), nil
}

func (c *cachedToken) Authenticate(ctx context.Context, r *http.Request) (auth.Info, error) {
	return authenticateFunc(c.authenticate).authenticate(ctx, r)
}

func (c *cachedToken) append(token string, info auth.Info, r *http.Request) error {
	return c.cache.Store(token, info, r)
}

func (c *cachedToken) revoke(token string, r *http.Request) error {
	return c.cache.Delete(token, r)
}

// NoOpAuthenticate implements Authenticate function, it return nil, NOOP error,
// commonly used when token refreshed/mangaed directly using cache or Append function,
// and there is no need to parse token and authenticate request.
func NoOpAuthenticate(ctx context.Context, r *http.Request, token string) (auth.Info, error) {
	return nil, NOOP
}