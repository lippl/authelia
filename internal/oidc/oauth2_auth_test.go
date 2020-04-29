package oidc

import (
	"testing"

	"github.com/authelia/authelia/internal/mocks"
	"github.com/stretchr/testify/suite"
)

type OAuth2AuthSuite struct {
	suite.Suite

	mock *mocks.MockAutheliaCtx
}

func (s *OAuth2AuthSuite) SetupTest() {
	s.mock = mocks.NewMockAutheliaCtx(s.T())
}

func (s *OAuth2AuthSuite) TearDownTest() {
	s.mock.Close()
}

func (s *OAuth2AuthSuite) TestShouldReturn302() {
	AuthEndpointGet(s.mock.Ctx)
}

func TestRunOAuth2AuthSuite(t *testing.T) {
	suite.Run(t, new(OAuth2AuthSuite))
}
