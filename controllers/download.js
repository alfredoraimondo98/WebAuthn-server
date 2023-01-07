

exports.downloadApp = (req, res, next) => {
    console.log("download app")
    const file = './public/downloads/webauthn-fido2-wallet-algorand-macos-win32 Setup 0.0.1.exe';
    res.download(file); // Set disposition and send it.
}