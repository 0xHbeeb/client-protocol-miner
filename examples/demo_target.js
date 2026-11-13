// Realistic minified web client snippet demonstrating dynamic request signing
(function(window) {
    const APP_SECRET = "sk_live_9f83ac0182bcf7401d93a82";
    const API_ENDPOINT = "https://api.dexexchange.io/v1/orders";

    function computeSignature(path, params, timestamp, nonce) {
        // Sort keys alphabetically
        const sortedParams = Object.keys(params).sort().map(k => k + "=" + params[k]).join("&");
        const payload = path + "|" + sortedParams + "|" + timestamp + "|" + nonce;
        
        // Compute HMAC-SHA256 signature
        const signature = CryptoJS.HmacSHA256(payload, APP_SECRET).toString(CryptoJS.enc.Hex);
        return signature;
    }

    // Axios interceptor applying signature headers
    axios.interceptors.request.use(async (config) => {
        const timestamp = Date.now().toString();
        const nonce = Math.random().toString(36).substring(2, 10);
        const sig = computeSignature(config.url, config.params || {}, timestamp, nonce);

        config.headers.set("X-Signature", sig);
        config.headers.set("X-Timestamp", timestamp);
        config.headers.set("X-Nonce", nonce);
        return config;
    });

})(window);
