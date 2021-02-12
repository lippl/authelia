import {
    CompletePushNotificationSignInPath,
    InitiateDuoDeviceSelectionPath,
    CompleteDuoDeviceSelectionPath,
} from "./Api";
import { PostWithOptionalResponse, Get } from "./Client";
import { SignInResponse } from "./SignIn";

interface CompleteU2FSigninBody {
    targetURL?: string;
}

export function completePushNotificationSignIn(targetURL: string | undefined) {
    const body: CompleteU2FSigninBody = {};
    if (targetURL) {
        body.targetURL = targetURL;
    }
    return PostWithOptionalResponse<SignInResponse>(CompletePushNotificationSignInPath, body);
}

export interface DuoDevicesGetResponse {
    result: string;
    devices: DuoDevice[];
}

export interface DuoDevice {
    device: string;
    display_name: string;
    capabilities: string[];
}
export async function initiateDuoDeviceSelectionProcess() {
    return Get<DuoDevicesGetResponse>(InitiateDuoDeviceSelectionPath);
}

export interface DuoDevicePostRequest {
    device: string;
    method: string;
}
export async function completeDuoDeviceSelectionProcess(device: DuoDevicePostRequest) {
    return PostWithOptionalResponse(CompleteDuoDeviceSelectionPath, { device: device.device, method: device.method });
}
