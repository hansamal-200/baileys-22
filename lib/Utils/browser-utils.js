import { platform, release } from 'os';
import { proto } from '../../WAProto/index.js';
const PLATFORM_MAP = {
    aix: 'AIX',
    darwin: 'Mac OS',
    win32: 'Windows',
    android: 'Android',
    freebsd: 'FreeBSD',
    openbsd: 'OpenBSD',
    sunos: 'Solaris',
    linux: undefined,
    haiku: undefined,
    cygwin: undefined,
    netbsd: undefined
};
export const Browsers = {
    ubuntu: browser => ['Ubuntu', browser, '22.04.4'],
    macOS: browser => ['Mac OS', browser, '14.4.1'],
    baileys: browser => ['Baileys', browser, '6.5.0'],
    windows: browser => ['Windows', browser, '10.0.22631'],
    android: browser => [browser, 'Android', ''],
    /** The appropriate browser based on your OS & release */
    appropriate: browser => [PLATFORM_MAP[platform()] || 'Ubuntu', browser, release()]
};
export const getPlatformId = (browser) => {
    const upper = browser.toUpperCase()
    if (upper === 'ANDROID') {
        return proto.DeviceProps.PlatformType['ANDROID_PHONE'].toString()
    }
    const platformType = proto.DeviceProps.PlatformType[upper]
    return platformType ? platformType.toString() : '1' // chrome
}

export const isAndroidBrowser = (browser) => {
    return browser[1]?.toUpperCase() === 'ANDROID'
}
//# sourceMappingURL=browser-utils.js.map