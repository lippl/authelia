package handlers

import (
	"fmt"
	"net/url"

	"github.com/authelia/authelia/internal/authentication"
	"github.com/authelia/authelia/internal/duo"
	"github.com/authelia/authelia/internal/middlewares"
	"github.com/authelia/authelia/internal/utils"
)

// SecondFactorDuoPost handler for sending a push notification via duo api.
func SecondFactorDuoPost(duoAPI duo.API) middlewares.RequestHandler {
	return func(ctx *middlewares.AutheliaCtx) {
		var requestBody signDuoRequestBody
		err := ctx.ParseBody(&requestBody)

		if err != nil {
			handleAuthenticationUnauthorized(ctx, err, mfaValidationFailedMessage)
			return
		}

		userSession := ctx.GetSession()
		remoteIP := ctx.RemoteIP().String()
		device, method, err := ctx.Providers.StorageProvider.LoadPreferredDuoDevice(userSession.Username)
		if err != nil {
			handleAuthenticationUnauthorized(ctx, err, mfaValidationFailedMessage)
			return
		}

		ctx.Logger.Debugf("Starting Duo Push Auth Attempt for %s from IP %s", userSession.Username, remoteIP)

		values := url.Values{}
		values.Set("username", userSession.Username)
		values.Set("ipaddr", remoteIP)
		values.Set("factor", method)

		if !utils.IsStringInSlice(method, duo.PossibleMethods) {
			handleAuthenticationUnauthorized(ctx, fmt.Errorf("Duo method not supported: %s", method), mfaValidationFailedMessage)
			return
		}

		if method == duo.Push {
			values.Set("device", device)
			if userSession.DisplayName != "" {
				values.Set("display_username", userSession.DisplayName)
			}
			if requestBody.TargetURL != "" {
				values.Set("pushinfo", fmt.Sprintf("target%%20url=%s", requestBody.TargetURL))
			}
		}
		// if method == duo.Phone || method == duo.SMS {
		// 	values.Set("device", device)
		// }
		// if method == duo.OTP {
		// 	values.Set("factor", "passcode")
		// 	if requestBody.Passcode != "" {
		// 		values.Set("passcode", requestBody.Passcode)
		// 	}
		// }

		authResponse, err := duoAPI.AuthCall(values, ctx)
		if err != nil {
			handleAuthenticationUnauthorized(ctx, fmt.Errorf("Duo API errored: %s", err), mfaValidationFailedMessage)
			return
		}

		if authResponse.Result != testResultAllow {
			ctx.ReplyUnauthorized()
			return
		}

		err = ctx.Providers.SessionProvider.RegenerateSession(ctx.RequestCtx)
		if err != nil {
			handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to regenerate session for user %s: %s", userSession.Username, err), mfaValidationFailedMessage)
			return
		}

		userSession.AuthenticationLevel = authentication.TwoFactor
		err = ctx.SaveSession(userSession)

		if err != nil {
			handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to update authentication level with Duo: %s", err), mfaValidationFailedMessage)
			return
		}

		Handle2FAResponse(ctx, requestBody.TargetURL)
	}
}
