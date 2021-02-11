package handlers

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/authelia/authelia/internal/duo"
	"github.com/authelia/authelia/internal/middlewares"
	"github.com/authelia/authelia/internal/utils"
)

// SecondFactorDuoDevicesGet handler for retrieving available devices and capabilities from duo api.
func SecondFactorDuoDevicesGet(duoAPI duo.API) middlewares.RequestHandler {
	return func(ctx *middlewares.AutheliaCtx) {
		userSession := ctx.GetSession()
		values := url.Values{}
		values.Set("username", userSession.Username)

		ctx.Logger.Debugf("Starting Duo PreAuth for %s", userSession.Username)

		preauthResponse, err := duoAPI.PreauthCall(values, ctx)
		if err != nil {
			ctx.Error(fmt.Errorf("Duo API errored: %s", err), operationFailedMessage)
			return
		}

		if preauthResponse.Result == "auth" {
			var selectedDevices []DuoDevice
			for _, device := range preauthResponse.Devices {
				var selectedMethods []string
				for _, method := range duo.PossibleMethods {
					if utils.IsStringInSlice(method, device.Capabilities) {
						selectedMethods = append(selectedMethods, method)
					}
				}

				if len(selectedMethods) > 0 {
					selectedDevices = append(selectedDevices, DuoDevice{
						Device:       device.Device,
						DisplayName:  device.DisplayName,
						Capabilities: selectedMethods,
					})
				}
			}

			if len(selectedDevices) < 1 {
				ctx.Logger.Debugf("No applicable device/method available for Duo user %s", userSession.Username)
				ctx.SetJSONBody(DuoDevicesResponse{Result: "enroll"})
				return
			}

			ctx.SetJSONBody(DuoDevicesResponse{Result: "auth", Devices: selectedDevices})
			return

		}
		if preauthResponse.Result == "allow" {
			ctx.Logger.Debugf("Device selection not possible for user %s, because Duo authentication was bypassed - Defaults to Auto Push", userSession.Username)
			ctx.SetJSONBody(DuoDevicesResponse{Result: "allow"})
			return
		}
		if preauthResponse.Result == "enroll" {
			ctx.Logger.Debugf("Duo User not enrolled: %s", userSession.Username)
			ctx.SetJSONBody(DuoDevicesResponse{Result: "enroll"})
			return
		}
		if preauthResponse.Result == "deny" {
			ctx.Logger.Debugf("Duo User not allowed to authenticate: %s", userSession.Username)
			ctx.SetJSONBody(DuoDevicesResponse{Result: "deny"})
			return
		}

		ctx.Error(fmt.Errorf("Duo PreAuth API errored for %s: %s", userSession.Username, preauthResponse), operationFailedMessage)

	}

}

// SecondFactorDuoDevicePost update the user preferences regarding Duo device and method.
func SecondFactorDuoDevicePost(ctx *middlewares.AutheliaCtx) {
	device := DuoDeviceBody{}

	err := ctx.ParseBody(&device)
	if err != nil {
		ctx.Error(err, operationFailedMessage)
		return
	}

	if !utils.IsStringInSlice(device.Method, duo.PossibleMethods) {
		ctx.Error(fmt.Errorf("Unknown method '%s', it should be one of %s", device.Method, strings.Join(duo.PossibleMethods, ", ")), operationFailedMessage)
		return
	}

	userSession := ctx.GetSession()
	ctx.Logger.Debugf("Save new preferred Duo device and method of user %s to %s using %s", userSession.Username, device.Device, device.Method)
	err = ctx.Providers.StorageProvider.SavePreferredDuoDevice(userSession.Username, device.Device, device.Method)

	if err != nil {
		ctx.Error(fmt.Errorf("Unable to save new preferred Duo device and method: %s", err), operationFailedMessage)
		return
	}

	ctx.ReplyOK()
}
