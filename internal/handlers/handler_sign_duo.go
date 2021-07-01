package handlers

import (
	"fmt"
	"net/url"

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

			ctx.Logger.Debugf("No previous Device saved - Starting Duo PreAuth for %s", userSession.Username)
			result, message, devices, enrollUrl, err := DuoPreAuth(duoAPI, ctx)

			if err != nil {
				handleAuthenticationUnauthorized(ctx, fmt.Errorf("Duo PreAuth API errored: %s", err), mfaValidationFailedMessage)
				return
			}

			if result == "enroll" {
				ctx.Logger.Debugf("Duo User not enrolled: %s", userSession.Username)
				ctx.SetJSONBody(DuoSignResponse{Result: result, EnrollURL: enrollUrl})
				return
			}

			if result == "deny" {
				handleAuthenticationUnauthorized(ctx, fmt.Errorf("Duo User %s not allowed to authenticate: %s", userSession.Username, message), mfaValidationFailedMessage)
				ctx.ReplyUnauthorized()

				return
			}

			if result == "allow" {
				ctx.Logger.Debugf("Duo authentication was bypassed for user %s", userSession.Username)
				Handle2FAResponse(ctx, requestBody.TargetURL)
				return
			}

			if result == "auth" {
				if devices == nil {
					ctx.Logger.Debugf("No applicable device/method available for Duo user %s", userSession.Username)
					ctx.SetJSONBody(DuoSignResponse{Result: "enroll"})
					return
				}
				if len(devices) > 1 {
					ctx.Logger.Debugf("Multiple devices available for Duo user %s - require selection", userSession.Username)
					ctx.SetJSONBody(DuoSignResponse{Result: result, Devices: devices})
					return
				}
				if len(devices[0].Capabilities) > 1 {
					ctx.Logger.Debugf("Multiple methods available for Duo user %s - require selection", userSession.Username)
					ctx.SetJSONBody(DuoSignResponse{Result: result, Devices: devices})
					return
				}

				device = devices[0].Device
				method = devices[0].Capabilities[0]
				ctx.Logger.Debugf("Exactly one device(%s) and method(%s) found - Saving as new preferred Duo device and method for user %s", devices[0].Device, devices[0].Capabilities[0], userSession.Username)

				err = ctx.Providers.StorageProvider.SavePreferredDuoDevice(userSession.Username, device, method)
				if err != nil {
					ctx.Logger.Warnf("Unable to save new preferred Duo device and method: %s", err)
					ctx.ReplyUnauthorized()
					return
				}
			}
		}

		ctx.Logger.Debugf("Starting Duo Push Auth Attempt for %s from IP %s", userSession.Username, remoteIP)

		values := url.Values{}
		values.Set("username", userSession.Username)
		values.Set("ipaddr", remoteIP)
		values.Set("factor", method)

		if !utils.IsStringInSlice(method, duo.PossibleMethods) {
			ctx.Logger.Debugf("%s Preffered Duo method not supported: %s", method, userSession.Username)
			ctx.SetJSONBody(DuoSignResponse{Result: "auth"})
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

		userSession.SetTwoFactor(ctx.Clock.Now())

		err = ctx.SaveSession(userSession)
		if err != nil {
			handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to update authentication level with Duo: %s", err), mfaValidationFailedMessage)
			return
		}

		if userSession.OIDCWorkflowSession != nil {
			handleOIDCWorkflowResponse(ctx)
		} else {
			Handle2FAResponse(ctx, requestBody.TargetURL)
		}
	}
}
