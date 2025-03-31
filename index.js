//
// Proxy Backblaze S3 compatible API requests, sending notifications to a webhook
//
// Adapted from https://github.com/obezuk/worker-signed-s3-template
//
import { AwsClient } from 'aws4fetch'

const UNSIGNABLE_HEADERS = [
    // These headers appear in the request, but are never passed upstream
    'x-forwarded-proto',
    'x-real-ip',
    // We can't include accept-encoding in the signature because Cloudflare
    // sets the incoming accept-encoding header to "gzip, br", then modifies
    // the outgoing request to set accept-encoding to "gzip".
    // Not cool, Cloudflare!
    'accept-encoding',
    // Conditional headers are not consistently passed upstream
    'if-match',
    'if-modified-since',
    'if-none-match',
    'if-range',
    'if-unmodified-since',
];

// URL needs colon suffix on protocol, and port as a string
const HTTPS_PROTOCOL = "https:";
const HTTPS_PORT = "443";

// How many times to retry a range request where the response is missing content-range
const RANGE_RETRY_ATTEMPTS = 3;

// Define Cache TTL (1 month in seconds)
const BROWSER_CACHE_TTL_SECONDS = 2592000; // 30 * 24 * 60 * 60

// Filter out cf-* and any other headers we don't want to include in the signature
function filterHeaders(headers, env) {
    // Suppress irrelevant IntelliJ warning
    // noinspection JSCheckFunctionSignatures
    return new Headers(Array.from(headers.entries())
        .filter(pair => !(
            UNSIGNABLE_HEADERS.includes(pair[0])
            || pair[0].startsWith('cf-')
            || ('ALLOWED_HEADERS' in env && !env['ALLOWED_HEADERS'].includes(pair[0]))
        ))
    );
}

// Helper function to create a Response suitable for HEAD requests (no body)
function createHeadResponse(response) {
    // Clone headers to make them mutable
    const newHeaders = new Headers(response.headers);
    return new Response(null, {
        headers: newHeaders, // Use the cloned headers
        status: response.status,
        statusText: response.statusText
    });
}

// --- NEW Helper Function to Add Cache Headers ---
// Takes an existing Response and returns a new one with updated Cache-Control
function addCacheHeaders(response, cacheTtlSeconds) {
    // Only cache successful responses
    if (!response.ok) {
        return response;
    }

    // Create new Headers object based on the response's headers
    const newHeaders = new Headers(response.headers);

    // Set the desired Cache-Control header (overwrites existing if present)
    newHeaders.set('Cache-Control', `public, max-age=${cacheTtlSeconds}`);

    // Return a new Response with the original body/status but modified headers
    // Note: response.body can only be read once. We pass the stream directly.
    return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: newHeaders
    });
}
// --- End NEW Helper Function ---


function isListBucketRequest(env, path) {
    const pathSegments = path.split('/');

    return (env['BUCKET_NAME'] === "$path" && pathSegments.length < 2) // https://endpoint/bucket-name/
        || (env['BUCKET_NAME'] !== "$path" && path.length === 0); // https://bucket-name.endpoint/ or https://endpoint/
}

// Supress IntelliJ's "unused default export" warning
// noinspection JSUnusedGlobalSymbols
export default {
    async fetch(request, env) {
        // Only allow GET and HEAD methods
        if (!['GET', 'HEAD'].includes(request.method)){
            return new Response(null, {
                status: 405,
                statusText: "Method Not Allowed"
            });
        }

        const url = new URL(request.url);

        // Incoming protocol and port is taken from the worker's environment.
        // Local dev mode uses plain http on 8787, and it's possible to deploy
        // a worker on plain http. B2 only supports https on 443
        url.protocol = HTTPS_PROTOCOL;
        url.port = HTTPS_PORT;

        // Remove leading slashes from path
        let path = url.pathname.replace(/^\//, '');
        // Remove trailing slashes
        path = path.replace(/\/$/, '');

        // Reject list bucket requests unless configuration allows it
        if (isListBucketRequest(env, path) && String(env['ALLOW_LIST_BUCKET']) !== "true") {
            return new Response(null, {
                status: 404,
                statusText: "Not Found"
            });
        }

        // Set RCLONE_DOWNLOAD to "true" to use rclone with --b2-download-url
        // See https://rclone.org/b2/#b2-download-url
        const rcloneDownload = String(env["RCLONE_DOWNLOAD"]) === 'true';

        // Set upstream target hostname.
        switch (env['BUCKET_NAME']) {
            case "$path":
                // Bucket name is initial segment of URL path
                url.hostname = env['B2_ENDPOINT'];
                break;
            case "$host":
                // Bucket name is initial subdomain of the incoming hostname
                url.hostname = url.hostname.split('.')[0] + '.' + env['B2_ENDPOINT'];
                break;
            default:
                // Bucket name is specified in the BUCKET_NAME variable
                url.hostname = env['BUCKET_NAME'] + "." + env['B2_ENDPOINT'];
                break;
        }

        // Certain headers, such as x-real-ip, appear in the incoming request but
        // are removed from the outgoing request. If they are in the outgoing
        // signed headers, B2 can't validate the signature.
        const headers = filterHeaders(request.headers, env);

        // Create an S3 API client that can sign the outgoing request
        const client = new AwsClient({
            "accessKeyId": env['B2_APPLICATION_KEY_ID'],
            "secretAccessKey": env['B2_APPLICATION_KEY'],
            "service": "s3",
        });

        // Save the request method, so we can process responses for HEAD requests appropriately
        const requestMethod = request.method;

        if (rcloneDownload) {
            if (env['BUCKET_NAME'] === "$path") {
                // Remove leading file/ prefix from the path
                url.pathname = path.replace(/^file\//, "");
            } else {
                // Remove leading file/{bucket_name}/ prefix from the path
                url.pathname = path.replace(/^file\/[^/]+\//, "");
            }
        }

        // Sign the outgoing request
        //
        // For HEAD requests Cloudflare appears to change the method on the outgoing request to GET (#18), which
        // breaks the signature, resulting in a 403. So, change all HEADs to GETs. This is not too inefficient,
        // since we won't read the body of the response if the original request was a HEAD.
        const signedRequest = await client.sign(url.toString(), {
            method: 'GET', // Always use GET upstream for signing consistency
            headers: headers
        });

        // For large files, Cloudflare will return the entire file, rather than the requested range
        // So, if there is a range header in the request, check that the response contains the
        // content-range header. If not, abort the request and try again.
        // See https://community.cloudflare.com/t/cloudflare-worker-fetch-ignores-byte-request-range-on-initial-request/395047/4
        if (signedRequest.headers.has("range")) {
            let attempts = RANGE_RETRY_ATTEMPTS;
            let response;
            let finalResponse; // Variable to hold the final response object

            do {
                let controller = new AbortController();
                response = await fetch(signedRequest.url, {
                    method: signedRequest.method,
                    headers: signedRequest.headers,
                    signal: controller.signal,
                });
                if (response.headers.has("content-range")) {
                    // Only log if it didn't work first time
                    if (attempts < RANGE_RETRY_ATTEMPTS) {
                        console.log(`Retry for ${signedRequest.url} succeeded - response has content-range header`);
                    }
                    // Break out of loop and use this response
                    finalResponse = response;
                    break;
                } else if (response.ok) {
                    attempts -= 1;
                    console.error(`Range header in request for ${signedRequest.url} but no content-range header in response. Will retry ${attempts} more times`);
                    // Do not abort on the last attempt, as we want to return the response
                    if (attempts > 0) {
                        // Abort the current fetch response body to release connection
                         if(response.body) {
                            // Consume the body to allow the connection to close cleanly
                           await response.body.cancel();
                        }
                       // controller.abort(); // controller.abort() seems less reliable here than consuming body
                    } else {
                       // Last attempt failed, use this response
                       finalResponse = response;
                    }
                } else {
                    // Response is not ok, so don't retry
                    finalResponse = response;
                    break;
                }
            } while (attempts > 0);

            if (!finalResponse) { // Should ideally not happen, but as a safeguard
                 finalResponse = response;
            }

            if (attempts <= 0 && !finalResponse.headers.has("content-range")) {
                console.error(`Tried range request for ${signedRequest.url} ${RANGE_RETRY_ATTEMPTS} times, but no content-range in response.`);
            }

            if (requestMethod === 'HEAD') {
                // Original request was HEAD, create a HEAD response
                const headResponse = createHeadResponse(finalResponse);
                // Add cache headers and return
                return addCacheHeaders(headResponse, BROWSER_CACHE_TTL_SECONDS);
            }

            // Return the final GET response after adding cache headers
            return addCacheHeaders(finalResponse, BROWSER_CACHE_TTL_SECONDS);

        } else {
             // --- Normal GET/HEAD request (no range header involved) ---

             // Send the signed request to B2
            const response = await fetch(signedRequest);

            if (requestMethod === 'HEAD') {
                // Original request was HEAD, create a HEAD response
                const headResponse = createHeadResponse(response);
                 // Add cache headers and return
                return addCacheHeaders(headResponse, BROWSER_CACHE_TTL_SECONDS);
            }

             // Return the upstream GET response after adding cache headers
            return addCacheHeaders(response, BROWSER_CACHE_TTL_SECONDS);
        }
    },
};
