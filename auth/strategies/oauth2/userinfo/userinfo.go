// Package userinfo provide auth strategy to authenticate,
// incoming HTTP requests using the oauth2/openid userinfo endpoint,
// as defined in OpenID Connect https://openid.net/specs/openid-connect-core-1_0.html#UserInfo.
// This authentication strategy makes it easy to introduce apps,
// into a oauth2 authorization framework to be used by resource servers or other internal servers.
package userinfo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/shaj13/go-guardian/v2/auth"
	"github.com/shaj13/go-guardian/v2/auth/claims"
	"github.com/shaj13/go-guardian/v2/auth/internal"
	"github.com/shaj13/go-guardian/v2/auth/strategies/oauth2"
	"github.com/shaj13/go-guardian/v2/auth/strategies/token"
)

const wwwauth = "WWW-Authenticate"

// GetAuthenticateFunc return function to authenticate request using oauth2/openid userinfo endpoint.
// The returned function typically used with the token strategy.
func GetAuthenticateFunc(addr string, opts ...auth.Option) token.AuthenticateFunc {
	return newUserInfo(addr, opts...).authenticate
}

// New return strategy authenticate request using oauth2/openid userinfo endpoint.
//
// New is similar to:
//
// 		fn := userinfo.GetAuthenticateFunc(addr, opts...)
// 		token.New(fn, cache, opts...)
//
func New(addr string, c auth.Cache, opts ...auth.Option) auth.Strategy {
	fn := GetAuthenticateFunc(addr, opts...)
	return token.New(fn, c, opts...)
}

func newUserInfo(addr string, opts ...auth.Option) *userinfo {
	uinfo := new(userinfo)
	uinfo.requester = &internal.Requester{
		Addr:              addr,
		Endpoint:          "",
		KeepUnmarshalling: true,
		Marshal:           json.Marshal,
		Unmarshal:         json.Unmarshal,
		AdditionalData: func(r *http.Request) {
			r.Header.Set("Accept", "application/json")
		},
		Client: &http.Client{
			Transport: &http.Transport{},
		},
	}
	uinfo.claimResolver = new(Claims)
	uinfo.errorResolver = new(oauth2.ResponseError)
	uinfo.opts = claims.VerifyOptions{}

	for _, opt := range opts {
		opt.Apply(uinfo.requester)
		opt.Apply(uinfo)
	}

	return uinfo
}

type userinfo struct {
	opts          claims.VerifyOptions
	claimResolver oauth2.ClaimsResolver
	errorResolver oauth2.ErrorResolver
	requester     *internal.Requester
}

func (i *userinfo) authenticate(ctx context.Context, r *http.Request, tokenstr string) (auth.Info, time.Time, error) { //nolint:lll
	autherr := i.errorResolver.New()
	authclaims := i.claimResolver.New()
	f := func(r *http.Request) {
		r.Header.Set("Authorization", string(token.Bearer)+" "+tokenstr)
	}
	fail := func(err error) (auth.Info, time.Time, error) {
		return nil, time.Time{}, fmt.Errorf("strategies/oauth2/userinfo: %w", err)
	}

	//nolint:bodyclose
	resp, err := i.requester.DoWithf(ctx, f, nil, authclaims, autherr)

	switch {
	case err != nil:
		return fail(err)
	case resp.StatusCode != http.StatusOK && resp.Body != http.NoBody:
		return fail(autherr)
	case resp.StatusCode != http.StatusOK && len(resp.Header.Get(wwwauth)) > len(token.Bearer):
		err := errorFromHeader(resp.Header.Get(wwwauth), autherr)
		return fail(err)
	case resp.StatusCode != http.StatusOK:
		err := fmt.Errorf("Authorization server returned %v status code", resp.StatusCode)
		return fail(err)
	}

	if err := authclaims.Verify(i.opts); err != nil {
		return fail(err)
	}
	info := authclaims.Resolve()
	scope := oauth2.Scope(authclaims)
	token.WithNamedScopes(info, scope...)
	return info, oauth2.ExpiresAt(authclaims), nil
}

func errorFromHeader(header string, autherr oauth2.ErrorResolver) error {
	result := make(map[string]string)
	bearer := string(token.Bearer)
	header = strings.TrimSpace(header)
	if len(header) > len(bearer) && header[:len(bearer)] == bearer { //nolint:staticcheck
		header = header[len(bearer):]
	}

	list := strings.Split(header, ",")

	for _, v := range list {
		kv := strings.SplitN(v, "=", 2)
		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])
		value, _ = strconv.Unquote(value)
		result[key] = value
	}

	buf, err := json.Marshal(&result)
	if err != nil {
		return err
	}

	if err = json.Unmarshal(buf, autherr); err != nil {
		return err
	}

	return autherr
}
